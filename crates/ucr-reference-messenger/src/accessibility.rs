/// Whether a Reference Messenger accessibility behavior is mandatory for completion.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AccessibilityRequirement {
    Required,
}

/// Logical text direction. UI layout must not encode left-to-right as protocol semantics.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextDirection {
    LeftToRight,
    RightToLeft,
}

/// Canon-required accessibility surface for a future concrete platform client.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AccessibilityContract {
    pub screen_reader_semantics: AccessibilityRequirement,
    pub keyboard_navigation: AccessibilityRequirement,
    pub text_scaling: AccessibilityRequirement,
    pub captions: AccessibilityRequirement,
    pub subtitles: AccessibilityRequirement,
    pub transcription_surfaces: AccessibilityRequirement,
    pub high_contrast: AccessibilityRequirement,
    pub rtl_layout: AccessibilityRequirement,
}

impl AccessibilityContract {
    /// Returns the mandatory Phase-40 presentation requirements without claiming platform proof.
    #[must_use]
    pub const fn canonical() -> Self {
        Self {
            screen_reader_semantics: AccessibilityRequirement::Required,
            keyboard_navigation: AccessibilityRequirement::Required,
            text_scaling: AccessibilityRequirement::Required,
            captions: AccessibilityRequirement::Required,
            subtitles: AccessibilityRequirement::Required,
            transcription_surfaces: AccessibilityRequirement::Required,
            high_contrast: AccessibilityRequirement::Required,
            rtl_layout: AccessibilityRequirement::Required,
        }
    }
}
