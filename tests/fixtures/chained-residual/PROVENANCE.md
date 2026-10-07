# Chained-residual recovery fixture

This is a small, synthetic format-level fixture, **not** a package produced by
the Crate packer. Its manifest models the residual dependency layout found in
early packages: `Current.wav` depends on `Master.wav`, which depends on
`Stem.wav`. The manifest deliberately lists the dependent file first.

`historical-layout.crate` contains standard FLAC streams, one shared WAV header,
and a plain JSON manifest. The three original WAVs are in `source/`. The fixture
tests only whether an independent decoder rebuilds the files in dependency order
and checks their original SHA-256 hashes. It contains no Crate encoder, transform
selection, or tuning implementation.
