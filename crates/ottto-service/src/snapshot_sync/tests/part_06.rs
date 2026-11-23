mod census_p2_kept_pipeline_tests {
    include!("../census_p2_kept_pipeline_tests.rs");
}
use census_p2_kept_pipeline_tests::{
    assert_listed_fold_absent, pipeline_transcript_line, PipelineCycle, PipelineFixture,
    PipelinePage, PipelineUpload, PIPELINE_FILE_BIRTH, PIPELINE_HELD_SESSION, PIPELINE_HOLD_CYCLE,
    PIPELINE_MACHINE_ID, PIPELINE_MAX_PAGES, PIPELINE_PAGE_FILES, PIPELINE_SESSIONS,
};
