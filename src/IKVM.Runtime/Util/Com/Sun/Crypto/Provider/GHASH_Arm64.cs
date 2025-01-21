#if NET6_0_OR_GREATER

using System;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.Arm;

namespace IKVM.Runtime.Util.Com.Sun.Crypto.Provider
{
    /// <summary>
    /// Arm implementation of the GHASH intrinsic functions.
    /// </summary>
    static class GHASH_Arm64
    {
        private static ReadOnlySpan<long> P => [0x87, 0x87];

        /// <summary>
        /// Returns <c>true</c> if the current platform is supported by this implementation.
        /// </summary>
        public static bool IsSupported => Aes.IsSupported && AdvSimd.Arm64.IsSupported;

        /// <summary>
        /// Implementation of com.sun.crypto.provider.GHASH.processBlocks for the Arm platform.
        /// Derived from the OpenJDK C code 'stubGenerator_aarch64.cpp:generate_ghash_processBlocks'.
        /// Keep the structure of the body of this method as close to the orignal C code as possible to facilitate porting changes.
        /// </summary>
        /// <param name="data"></param>
        /// <param name="blocks"></param>
        /// <param name="state"></param>
        /// <param name="subH"></param>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static void ProcessBlocks(Span<long> state, ReadOnlySpan<long> subH, ReadOnlySpan<byte> data, int blocks)
        {
            var vzr = Vector128<byte>.Zero;
            var v0 = Vector128Util.Create((ReadOnlySpan<long>)state);
            var v1 = Vector128Util.Create(subH);
            v0 = AdvSimd.ReverseElement8(v0);
            v0 = AdvSimd.Arm64.ReverseElementBits(v0.AsByte()).AsInt64();
            v1 = AdvSimd.ReverseElement8(v1);
            v1 = AdvSimd.Arm64.ReverseElementBits(v1.AsByte()).AsInt64();

            var v26 = Vector128Util.Create(P);

            var v16 = AdvSimd.ExtractVector128(v1.AsByte(), v1.AsByte(), 0x08);
            v16 = AdvSimd.Xor(v16, v1.AsByte());

        ghash_loop:
            var v2 = Vector128Util.LoadUnsafe(ref MemoryMarshal.GetReference(data), 0x10);
            v2 = AdvSimd.Arm64.ReverseElementBits(v2);
            v2 = AdvSimd.Xor(v0.AsByte(), v2);

            (var v5, var v7) = GHashMultiply(v1, v2, v16);
            v0 = GHashReduce(v5, v7, v26, vzr);

            if ((--blocks) != 0)
            {
                goto ghash_loop;
            }

            v1 = AdvSimd.ReverseElement8(v0);
            v1 = AdvSimd.Arm64.ReverseElementBits(v1.AsByte()).AsInt64();
            v1.AsInt64().CopyTo(state);
        }

        private static (Vector128<long> Lower, Vector128<long> Upper) GHashMultiply(Vector128<long> a, Vector128<byte> b, Vector128<byte> a1_xor_a0)
        {
            var tmp1 = AdvSimd.ExtractVector128(b, b, 0x08);
            var result_hi = Aes.PolynomialMultiplyWideningUpper(b.AsInt64(), a);
            tmp1 = AdvSimd.Xor(tmp1, b);
            var result_lo = Aes.PolynomialMultiplyWideningLower(b.GetLower().AsInt64(), a.GetLower());
            var tmp2 = Aes.PolynomialMultiplyWideningLower(tmp1.GetLower().AsInt64(), a1_xor_a0.GetLower().AsInt64());

            var tmp4 = AdvSimd.ExtractVector128(result_lo.AsByte(), result_hi.AsByte(), 0x08);
            var tmp3 = AdvSimd.Xor(result_hi, result_lo);
            tmp2 = AdvSimd.Xor(tmp2, tmp4.AsInt64());
            tmp2 = AdvSimd.Xor(tmp2, tmp3);

            result_hi = AdvSimd.Insert(tmp2, 0, 1);
            result_lo = AdvSimd.Insert(tmp2, 1, 0);

            return (result_lo, result_hi);
        }

        private static Vector128<long> GHashReduce(Vector128<long> lo, Vector128<long> hi, Vector128<long> p, Vector128<byte> z)
        {
            var result = Aes.PolynomialMultiplyWideningUpper(hi, p);
            var t1 = AdvSimd.ExtractVector128(result.AsByte(), z, 8);
            hi = AdvSimd.Xor(hi, t1.AsInt64());
            t1 = AdvSimd.ExtractVector128(z, result.AsByte(), 8);
            lo = AdvSimd.Xor(lo, t1.AsInt64());
            result = Aes.PolynomialMultiplyWideningLower(hi.GetLower(), p.GetLower());
            result = AdvSimd.Xor(lo, result);
            return result;
        }
    }
}

#endif