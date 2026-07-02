# nanom on the GPU — device readiness

nanom's zero-copy decode path is written to run **unchanged on a GPU**. This
page states precisely what is device-ready, what is verified, and the exact
steps to launch the bulk decode on CUDA/HIP. (No GPU was available in the
environment where this was built, so the device path is **compile-ready and
CPU-verified**, not yet run on silicon — that distinction is kept honest below.)

## The model

Bulk decode is a grid of independent tasks, one per packet: each decodes its
packet and scatters the result into pre-sized SoA columns **at its own row
index**. Writes are disjoint across tasks, so there are no locks, no atomics, no
`push_back`, and no per-task allocation — the same reason it parallelizes on CPU
threads is the reason it maps to a GPU grid. See `include/nanom/bulk.hpp`.

```
host: scan (serial) ─► pkt_ref[]  ─copy─►  device: kernel<<<grid>>> {
                        column bufs ─copy─►    i = tid;
                                               Row r; decode_row(pkt[i], r);
                                               scatter_row(cols, i, r);   // disjoint
                                           }  ◄─copy─ column bufs ─► nanoarrow / Lance
```

## What is device-ready (annotated `NANOM_HD`)

The whole overlay/decode call tree is marked `NANOM_HD` (→ `__host__ __device__`
under a CUDA/HIP compiler, nothing on a host build):

- `input` accessors; `endian_scalar::get/set`; `read_bits`; `decode_field`;
  `assign_field`; `field_bit_offsets`; `view<T>::get/raw/to_struct`.
- `nm::scatter_row` / `detail::scatter_one` and `nm::pkt_ref` in `bulk.hpp`.

These are POD-in/POD-out, allocation-free, exception-free, and touch no globals.
`static_assert`s enforce the transfer contract: `pkt_ref` and every bulk `Row`
are `std::is_trivially_copyable` (memcpy-able to device memory).

## What is **not** device code (host-only, by design)

- `error::render` (builds a `std::string`) — only ever called after a failure,
  on the host.
- The pcap/pcapng **scan** (`scan_blocks`) — inherently serial; run it on the
  host, ship the resulting `pkt_ref[]` (offsets into the device buffer).
- The allocating combinators (`many*`, `separated_list*`, `soa` storage) — the
  device kernel uses the fixed-shape overlay path, not these.

## What is verified here (CPU)

`examples/nanotins_parity/pcap_bulk.cpp` runs the identical kernel over a CPU
thread pool (`nm::par_exec`, the stand-in for a device grid):

- **Correctness**: the parallel result is **bit-identical** to the serial
  `nm::seq_exec` path (checked column-by-column; the `bulk_parallel_equals_serial`
  test fails the build otherwise).
- **Scaling**: ~1.9× on 4 cores for a memory-bound streaming decode (672k
  packets) — the structural win a per-packet scalar walk (nanom's or nanotins')
  cannot reach. On a GPU's bandwidth + thread count this is where the columnar
  decode pulls decisively ahead.

## Launching on CUDA / HIP (the remaining step)

1. Build the translation unit with `nvcc`/`clang++ --cuda-gpu-arch=…` (or HIP).
   `NANOM_HD` auto-expands to `__host__ __device__` (see the guard in
   `nanom.hpp`); no source change.
2. Host: `scan_blocks` → `pkt_ref[]`. `cudaMemcpy` the packet bytes and the
   `pkt_ref[]` to the device; `cudaMalloc` one buffer per column
   (`bulk_table::columns()[c].elem_bytes * n`).
3. Launch one thread per packet:
   ```cuda
   __global__ void k(const nm::pkt_ref* p, std::size_t n,
                     std::byte* const* col, const std::size_t* elem, std::uint8_t* valid) {
     std::size_t i = blockIdx.x * blockDim.x + threadIdx.x;
     if (i >= n) return;
     Row r{};
     if (decode_row(p[i], r)) { nm::scatter_row<Row>(col, elem, i, r); valid[i] = 1; }
   }
   ```
   `decode_row` and `scatter_row` are already `NANOM_HD` — this kernel is the CPU
   `bulk_decode` body verbatim.
4. Copy the column buffers back (or keep them on-device for a GPU Arrow/Lance
   writer). They are already in Arrow layout (`bulk_table::columns()[c].arrow`).

The only device-specific code you write is the ~6-line launcher in step 3; the
parser, the field decode, and the SoA scatter are the same host-verified code.

## Honest status

| piece | state |
|---|---|
| decode path annotated `NANOM_HD` | ✅ in tree |
| POD, no-alloc, trivially-copyable kernel + I/O | ✅ `static_assert`-enforced |
| disjoint-write SoA scatter | ✅ `bulk.hpp` |
| CPU-parallel bulk (grid stand-in) | ✅ built, tested bit-identical, ~1.9×/4 cores |
| actual CUDA/HIP launch | ⬜ not run here (no GPU); ~6-line launcher above |
