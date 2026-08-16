use std::collections::VecDeque;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IngestStatus {
    Queued,
    InReview,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct IngestRecord {
    pub lane: String,
    pub payload: Vec<u8>,
    pub received_at: u64,
    pub status: IngestStatus,
}

impl IngestRecord {
    pub fn new(lane: &str, payload: Vec<u8>) -> Self {
        let received_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            lane: lane.to_string(),
            payload,
            received_at,
            status: IngestStatus::Queued,
        }
    }
}

#[derive(Debug, Default)]
pub struct IngestPipeline {
    queue: VecDeque<IngestRecord>,
}

impl IngestPipeline {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn submit(&mut self, lane: &str, payload: Vec<u8>) {
        self.queue.push_back(IngestRecord::new(lane, payload));
    }

    pub fn next_pending(&mut self) -> Option<IngestRecord> {
        self.queue.pop_front()
    }

    pub fn len(&self) -> usize {
        self.queue.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn submit_and_retrieve_record() {
        let mut pipeline = IngestPipeline::new();
        assert!(pipeline.is_empty());

        pipeline.submit("ai_core", vec![1, 2, 3]);
        assert_eq!(pipeline.len(), 1);

        let record = pipeline.next_pending().unwrap();
        assert_eq!(record.lane, "ai_core");
        assert_eq!(record.status, IngestStatus::Queued);
        assert!(pipeline.is_empty());
    }

    #[test]
    fn fifo_order_preserved() {
        let mut pipeline = IngestPipeline::new();
        pipeline.submit("lane_a", vec![]);
        pipeline.submit("lane_b", vec![]);

        assert_eq!(pipeline.next_pending().unwrap().lane, "lane_a");
        assert_eq!(pipeline.next_pending().unwrap().lane, "lane_b");
    }
}
