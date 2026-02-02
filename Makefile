build:
	RUSTFLAGS="-A warnings" cargo build --release

test:
	RUSTFLAGS="-A warnings" cargo test --release

clean:
	cargo clean

.PHONY: build test clean