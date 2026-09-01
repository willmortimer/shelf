//! Human-verifiable short authentication string for enrollment.

/// Six-word fingerprint derived from a transcript hash.
#[must_use]
pub fn sas_words(transcript: &[u8]) -> [String; 6] {
    let hash = blake3::hash(transcript);
    let bytes = hash.as_bytes();
    [
        WORD[bytes[0] as usize].to_string(),
        WORD[bytes[1] as usize].to_string(),
        WORD[bytes[2] as usize].to_string(),
        WORD[bytes[3] as usize].to_string(),
        WORD[bytes[4] as usize].to_string(),
        WORD[bytes[5] as usize].to_string(),
    ]
}

/// Space-separated SAS string.
#[must_use]
pub fn sas_display(transcript: &[u8]) -> String {
    sas_words(transcript).join(" ")
}

const WORD: [&str; 256] = [
    "able", "acid", "acre", "aged", "aide", "aims", "air", "akin", "alas", "ally", "aloe", "also",
    "alto", "amid", "anew", "anon", "apex", "arch", "area", "aria", "arid", "army", "arts", "ash",
    "asks", "atom", "aunt", "auto", "avid", "away", "axis", "axis", "babe", "back", "bail", "bait",
    "bake", "bald", "ball", "band", "bane", "bang", "bank", "bare", "bark", "barn", "base", "bash",
    "bask", "bath", "bats", "bawl", "bead", "beak", "beam", "bean", "bear", "beat", "beck", "beds",
    "beef", "been", "beep", "bees", "beet", "bell", "belt", "bend", "bent", "best", "beta", "bias",
    "bide", "bike", "bile", "bill", "bind", "bird", "bite", "bits", "blab", "bled", "blew", "blob",
    "blob", "blot", "blow", "blue", "blur", "boar", "boat", "bode", "body", "boil", "bold", "bolt",
    "bond", "bone", "bong", "bony", "book", "boom", "boon", "boot", "bore", "born", "boss", "both",
    "bout", "bowl", "bows", "boxy", "brad", "brag", "bran", "brat", "bray", "bred", "brew", "brim",
    "brow", "buck", "buds", "buff", "bugs", "bulb", "bulk", "bull", "bump", "bunk", "buns", "buoy",
    "burn", "burr", "bury", "bush", "busk", "bust", "busy", "buts", "buzz", "byte", "cabs", "cafe",
    "cage", "cake", "calf", "call", "calm", "came", "camp", "cane", "cape", "caps", "card", "care",
    "carp", "cars", "cart", "case", "cash", "cask", "cast", "cats", "cave", "caws", "cede", "cell",
    "cent", "chap", "char", "chat", "chef", "chew", "chic", "chin", "chip", "chop", "chow", "chug",
    "chum", "cite", "city", "clad", "clam", "clan", "clap", "claw", "clay", "clef", "clip", "clod",
    "clog", "clot", "club", "clue", "coal", "coat", "coax", "code", "coil", "coin", "coke", "cola",
    "cold", "colt", "coma", "comb", "come", "cone", "cook", "cool", "coop", "cope", "cops", "copy",
    "cord", "core", "cork", "corn", "cost", "cosy", "cots", "coup", "cove", "cowl", "cozy", "crab",
    "crag", "cram", "crew", "crib", "crop", "crow", "crud", "crux", "cube", "cubs", "cues", "cuff",
    "cull", "cult", "cups", "curb", "curd", "cure", "curl", "curt", "cusp", "cute", "cuts", "cyan",
    "cyst", "czar", "dabs", "dado",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_is_six_words_and_stable() {
        let a = sas_display(b"transcript-one");
        let b = sas_display(b"transcript-one");
        let c = sas_display(b"transcript-two");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.split_whitespace().count(), 6);
    }
}
