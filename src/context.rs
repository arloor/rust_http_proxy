use tokio::time::Instant;

pub struct Context {
    pub instant: Instant,
    pub upgraded: bool,
}

impl Default for Context {
    fn default() -> Self {
        Self {
            instant: Instant::now(),
            upgraded: false,
        }
    }
}

impl Context {
    pub fn refresh(&mut self) {
        self.instant = Instant::now();
    }
    pub fn set_upgraded(&mut self, upgraded: bool) {
        self.upgraded = upgraded;
    }
    pub fn snapshot(&self) -> (Instant, bool) {
        (self.instant, self.upgraded)
    }
}
