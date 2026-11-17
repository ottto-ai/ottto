include!("tests/part_01.rs");
include!("tests/part_02.rs");
include!("tests/part_03.rs");
include!("tests/part_04.rs");
include!("tests/part_05.rs");
include!("../retry_integrated_driver.rs");
include!("../retry_owned_rotation.rs");
include!("../retry_bounded_native_tests.rs");
include!("../retry_live_native_tests.rs");
include!("continuation_prepare_tests.rs");
include!("tests/part_06.rs");
// Main's original shared pipeline assertions run at the production OFF
// default, independently of the explicit-ON containment fixtures above.

include!("claude_request_census_pipeline_tests.rs");
include!("tests/part_07.rs");
include!("request_identity_pipeline_tests.rs");
include!("tests/part_08.rs");
