# Browser accessibility evidence

This checked-in browser surface is a concrete Phase-40 presentation adapter for the Reference Messenger.
It is intentionally **presentation-only**: it does not claim browser-native node, local transport, background execution, media capture, filesystem, or push capabilities.
All communication state and behavior remain owned by UCR and reached by the Reference Messenger through the public SDK/API.

The surface uses native keyboard controls and semantic landmarks, and exposes working LTR/RTL, 100/125/150% text-scale and high-contrast controls with screen-reader announcements. Caption/subtitle WebVTT tracks and a live transcript surface are included as media accessibility evidence.

`validate_accessibility.py` fails closed if semantic screen-reader structure, native keyboard operation, non-positive tab order, label/control binding, text scaling, captions, subtitles, transcript, contrast, forced-colors, focus-visible, interactive RTL wiring, or the browser presentation-only boundary disappears.
