//! QR codes as inline SVG, server-side: TOTP enrolment and the like need no
//! WebAssembly and no Trusted Types exemption this way.

pub fn qr_svg(data: &str) -> String {
    use qrcode::{render::svg, QrCode};
    match QrCode::new(data.as_bytes()) {
        // Dark modules on white even on a dark page: inverted codes fail on a
        // meaningful share of scanners.
        Ok(c) => c
            .render::<svg::Color>()
            .min_dimensions(160, 160)
            .dark_color(svg::Color("#000000"))
            .light_color(svg::Color("#ffffff"))
            .quiet_zone(true)
            .build(),
        Err(e) => {
            tracing::warn!("qr generation failed: {e}");
            String::new()
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders_svg() {
        let s = super::qr_svg("otpauth://totp/l4f:luki?secret=ABC&issuer=l4f");
        assert!(s.starts_with("<?xml") || s.starts_with("<svg"));
        assert!(s.contains("#000000"));
    }
}
