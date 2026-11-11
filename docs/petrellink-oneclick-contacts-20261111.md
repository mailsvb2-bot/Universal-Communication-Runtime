# PetrelLink consumer contacts integration (2026-11-11)

Base: `3b2b7f39015d43021b4e08c612d5c3e8ed7958c3`.

## Working code

- Browser one-shot Contacts Picker where supported; fallback to a single UTF-8 `.vcf`.
- Explicit SMS invitation composer with same-origin public contact locator.
- Searchable private contact list, rename and confirmation before delete.
- Friendly errors; calls use the existing authenticated `createUcrContactCallJourney.start()` only.
- Existing encrypted IndexedDB contact book remains the only owner of stored contacts.
- Native Android `ACTION_PICK`/SMS/dial/share adapters and iOS `CNContactPickerViewController`/SMS adapters, ready for application-level wiring.
- Rust static routes serve the same-origin ES modules without expanding backend contact discovery.

## Security invariants

No automatic upload of phone numbers, no contact-to-Identity inference, no address-book enumeration or phone-number lookup, no background SMS transmission, no new Device or Call authority. User-visible invitations are public locators, never Join grants.

## Known incomplete product work

- Native SDK adapters require integration into complete Android/iOS applications, not claimed production-ready.
- Contact selected from OS cannot be called via PetrelLink until peer accepts exchanged invitation and is saved as verified canonical UCR contact.
- No automatic WhatsApp/Telegram/Viber availability detection.
- Background notifications, device recovery UX and physical A↔B E2EE media evidence are separate P0/P1 gates.

## Basic tests

`node --test tests/consumer_phonebook.test.mjs`

`cargo fmt --all -- --check`

`cargo build --locked --release -p ucr-realtime-web`

Keep the production server at its last verified state until a full review and real-device proof.