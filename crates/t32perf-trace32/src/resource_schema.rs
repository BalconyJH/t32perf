//! Generated public JSON Schemas for parser-owned resource reports.

use std::collections::BTreeMap;

use schemars::{JsonSchema, schema_for};
use serde_json::{Value, json};

use crate::{
    STACK_USAGE_REPORT_SCHEMA, STATIC_RAM_REPORT_SCHEMA, StackUsageReport, StaticRamReport,
};

/// Generates every public resource-report JSON Schema owned by this crate.
#[must_use]
pub fn resource_schema_documents() -> BTreeMap<&'static str, Value> {
    BTreeMap::from([
        (
            "stack-usage-report.schema.json",
            schema_document::<StackUsageReport>(STACK_USAGE_REPORT_SCHEMA),
        ),
        (
            "static-ram-report.schema.json",
            static_ram_schema_document(),
        ),
    ])
}

fn static_ram_schema_document() -> Value {
    let mut schema = schema_document::<StaticRamReport>(STATIC_RAM_REPORT_SCHEMA);
    schema
        .as_object_mut()
        .expect("static RAM schema root is an object")
        .insert(
            "allOf".to_owned(),
            json!([
                {
                    "if": {
                        "properties": {
                            "schema": {"const": "t32perf.static-ram/gnu-ld-map-v1"}
                        },
                        "required": ["schema"]
                    },
                    "then": {
                        "properties": {
                            "elf": false,
                            "sections": {
                                "items": {
                                    "required": ["source_line"],
                                    "not": {"required": ["source_section_index"]}
                                }
                            }
                        }
                    }
                },
                {
                    "if": {
                        "properties": {
                            "schema": {"const": "t32perf.static-ram/elf-sections-v1"}
                        },
                        "required": ["schema"]
                    },
                    "then": {
                        "properties": {
                            "elf": {"$ref": "#/$defs/ElfStaticRamMetadata"},
                            "sections": {
                                "items": {
                                    "required": ["source_section_index"],
                                    "not": {"required": ["source_line"]}
                                }
                            }
                        },
                        "required": ["elf"]
                    }
                }
            ]),
        );
    schema
}

fn schema_document<T: JsonSchema>(id: &'static str) -> Value {
    let mut schema =
        serde_json::to_value(schema_for!(T)).expect("schema serialization is infallible");
    schema
        .as_object_mut()
        .expect("root schemas are objects")
        .insert("$id".to_owned(), Value::String(id.to_owned()));
    schema
}
