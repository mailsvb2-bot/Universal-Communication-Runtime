# Phase 17 Chat release gate

Phase 17 may be reported complete only when:

1. the exact PR head passes all six required repository checks;
2. the implementation remains a thin layer over canonical Conversation/Message/Delivery owners;
3. executable tests cover Direct send/transcript/read/typing, exact scope, and Phase-18 rejection;
4. `spec/chat.md` and ADR 0055 are repository-guarded;
5. the merged `main` SHA independently passes all six required checks;
6. README release truth states Phase 17 complete and Phase 18 Groups not started.
