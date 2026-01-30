build:
	RUSTFLAGS="-A warnings" cargo build --release

run:
	RUSTFLAGS="-A warnings" ./target/release/psy-cli server --listen-addr 0.0.0.0 --port 4000

test:
	RUSTFLAGS="-A warnings" cargo test --release

clean:
	cargo clean

.PHONY: build run test clean