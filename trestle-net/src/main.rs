use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

fn main() {
  trestle::cli::run_with_validator(trestle_net::validation::make_validator);
}
