use serde_json::json;
use t32perf_trace32::{ControllerFaultAction, DriverCommandRole, PerfOperation};

use crate::{
    app::{AppError, EXIT_OPERATIONAL},
    controller::ControllerRequestEnvelope,
};

const CMM_ABORT_MARKER_PREFIX: &str = "T32PERF_FAULT_ARMED cmm_abort perf_start";

pub(crate) fn external_hook_role(
    action: ControllerFaultAction,
) -> Result<DriverCommandRole, AppError> {
    match action {
        ControllerFaultAction::Trace32DisconnectAtStop => {
            Ok(DriverCommandRole::Trace32DisconnectAtStop)
        }
        ControllerFaultAction::DriverDisconnectAtExport => Err(AppError::operational(
            "driver_disconnect_at_export is owned by the exact t32mcp child handle, not an external fault hook",
        )),
        ControllerFaultAction::CmmAbortAtStart => Err(AppError::operational(
            "cmm_abort_at_start must use the official t32mcp abort operation, not an external fault hook",
        )),
    }
}

pub(crate) fn expected_cmm_abort_marker_envelope(
    request: &ControllerRequestEnvelope,
) -> Result<String, AppError> {
    if request.operation() != PerfOperation::Start
        || request.fault_action() != Some(ControllerFaultAction::CmmAbortAtStart)
    {
        return Err(AppError::operational(
            "CMM abort marker inspection requires the immutable cmm_abort_at_start request",
        ));
    }
    let initial_target_state = request
        .mcp()
        .execute
        .arguments
        .script_args
        .get("initial_target_state")
        .ok_or_else(|| {
            AppError::operational(
                "immutable cmm_abort_at_start request has no initial_target_state argument",
            )
        })?;
    if !matches!(initial_target_state.as_str(), "running" | "halted") {
        return Err(AppError::operational(
            "immutable cmm_abort_at_start request has an invalid initial_target_state argument",
        ));
    }
    Ok(format!(
        "{CMM_ABORT_MARKER_PREFIX} {} {initial_target_state}",
        request.binding().binding_sha256
    ))
}

/// Recognizes only the exact bounded unfinished wrapper emitted after the CMM
/// fault target has reached its fixed WAIT. Any additional line would make the
/// observation ambiguous and therefore cannot authorize abort confirmation.
pub(crate) fn has_exact_cmm_abort_marker(response: &str, expected: &str) -> bool {
    response
        .lines()
        .eq(["<NOT FINISHED>", "<CONTENT>", expected])
}

pub(crate) fn fault_injected_error_envelope(request: &ControllerRequestEnvelope) -> AppError {
    AppError {
        code: "CONTROLLER_FAULT_INJECTED",
        message: format!(
            "controller fault action `{}` was injected and its official upstream abort was durably confirmed",
            fault_action_name(
                request
                    .fault_action()
                    .expect("fault-injected result requires a fault request")
            )
        ),
        details: json!({
            "session_id": request.binding().session_id,
            "transaction_id": request.binding().transaction_id,
            "operation": request.operation(),
            "binding_sha256": request.binding().binding_sha256,
            "fault_action": request.fault_action(),
            "response_staged": false,
            "output_registered": false,
            "abort_confirmed": true,
            "recovery_required": true,
        }),
        exit_code: EXIT_OPERATIONAL,
    }
}

const fn fault_action_name(action: ControllerFaultAction) -> &'static str {
    match action {
        ControllerFaultAction::Trace32DisconnectAtStop => "trace32_disconnect_at_stop",
        ControllerFaultAction::DriverDisconnectAtExport => "driver_disconnect_at_export",
        ControllerFaultAction::CmmAbortAtStart => "cmm_abort_at_start",
    }
}

#[cfg(test)]
mod tests {
    use super::has_exact_cmm_abort_marker;

    #[test]
    fn cmm_abort_marker_wrapper_is_closed() {
        let marker = concat!(
            "T32PERF_FAULT_ARMED cmm_abort perf_start ",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa halted"
        );
        assert!(has_exact_cmm_abort_marker(
            &format!("<NOT FINISHED>\n<CONTENT>\n{marker}\n"),
            marker,
        ));
        for invalid in [
            format!("<FINISHED>\n<CONTENT>\n{marker}\n"),
            format!("<NOT FINISHED>\n<CONTENT>\nnoise\n{marker}\n"),
            format!("<NOT FINISHED>\n<CONTENT>\n{marker} extra\n"),
        ] {
            assert!(!has_exact_cmm_abort_marker(&invalid, marker));
        }
    }
}
