# Ideas (regarding `rand` RC)

Changes in the security dependencies may open ways to make the `trouble` code base simpler. These are listed here so they won't get forgotten, and can be introduced as secondary PR's, after `rand` 0.10 support is in.


## No double-Chacha'ing RNG seeds

The platform specific (hardware) RNG's could be used as-is, for providing a seed to the `trouble` RNG. Currently, at least with nRF52, the hardware RNG generates a seed, used for creating a `ChaCha` RNG, which again generates a seed, for another. This must be an unnecessary hoop, right?

Looking at these, the author noticed that actually all we'd need in getting things started is a *seed*, not an RNG. Doing this would further simplify the examples, most of all removing the need for `rand_core` dependency in them (rand stuff would remain as an internal dependency of `trouble`). Seems like a good direction (could already be brought in by this PR).


## Use of `getrandom`?

Changes in the APIs have made cryptographically strong RNG generation, without passing the `TRng` type around, possible.

Is this something we'd like to experiment with?

The benefit is mainly removing a bunch of generic parameters, especially in tests. As cons, test cases would need to be changed, since a new kind of RNG would be in use.

