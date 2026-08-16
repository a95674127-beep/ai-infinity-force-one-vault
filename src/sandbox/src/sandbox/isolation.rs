use crate::ingest::{IngestRecord, IngestStatus};

#[derive(Debug, PartialEq, Eq)]
pub enum SandboxError {
    PayloadTooLarge { max: usize, actual: usize },
    EmptyPayload,
}

pub type SandboxResult = Result<IngestRecord, SandboxError>;

pub struct SandboxRunner {
    pub max_payload_bytes: usize,
}

impl Default for SandboxRunner {
    fn default() -> Self {
        Self {
            max_payload_bytes: 1_048_576, // 1 MB default containment limit
        }
    }
}

impl SandboxRunner {
    pub fn new(max_payload_bytes: usize) -> Self {
        Self { max_payload_bytes }
    }

    /// Runs a single ingest record through containment checks.
    /// Deny-by-default: anything that doesn't explicitly pass is rejected.
    pub fn execute(&self, mut record: IngestRecord) -> SandboxResult {
        if record.payload.is_empty() {
            record.status = IngestStatus::Rejected;
            return Err(SandboxError::EmptyPayload);
        }

        if record.payload.len() > self.max_payload_bytes {
            record.status = IngestStatus::Rejected;
            return Err(SandboxError::PayloadTooLarge {
                max: self.max_payload_bytes,
                actual: record.payload.len(),
            });
        }

        record.status = IngestStatus::Accepted;
        Ok(record)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_payload() {
        let runner = SandboxRunner::default();
        let record = IngestRecord::new("ai_core", vec![1, 2, 3]);

        let result = runner.execute(record).unwrap();
        assert_eq!(result.status, IngestStatus::Accepted);
    }

    #[test]
    fn rejects_empty_payload() {
        let runner = SandboxRunner::default();
        let record = IngestRecord::new("ai_core", vec![]);

        let result = runner.execute(record);
        assert_eq!(result.unwrap_err(), SandboxError::EmptyPayload);
    }

    #[test]
    fn rejects_oversized_payload() {
        let runner = SandboxRunner::new(4);
        let record = IngestRecord::new("ai_core", vec![1, 2, 3, 4, 5]);

        let result = runner.execute(record);
        assert_eq!(
            result.unwrap_err(),
            SandboxError::PayloadTooLarge { max: 4, actual: 5 }
        );
    }
                   }
