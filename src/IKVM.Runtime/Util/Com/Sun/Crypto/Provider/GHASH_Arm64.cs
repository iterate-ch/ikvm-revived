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
    static class GHASH_Arm
    {
        private static ReadOnlySpan<long> P => [0x87, 0x87];

        /// <summary>
        /// Returns <c>true</c> if the current platform is supported by this implementation.
        /// </summary>
        public static bool IsSupported => AdvSimd.Arm64.IsSupported;

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
            var vzr = Vector128.Create(0);

            var v0 = Vector128Util.Create((ReadOnlySpan<long>)state).AsByte();
            var v1 = Vector128Util.Create(subH).AsByte();
            v0 = AdvSimd.ReverseElement16(v0.AsInt64()).AsByte();
            v0 = AdvSimd.Arm64.ReverseElementBits(v0);
            v1 = AdvSimd.ReverseElement16(v1.AsInt64()).AsByte();
            v1 = AdvSimd.Arm64.ReverseElementBits(v1);

            var v26 = Vector128Util.Create(P);

            var v16 = AdvSimd.ExtractVector128(v1, v1, 0x08);
            v16 = AdvSimd.Xor(v16, v1);

        ghash_loop:
            var v2 = Vector128Util.LoadUnsafe(ref MemoryMarshal.GetReference(data), 0x10).AsInt32();
            v2 = AdvSimd.Arm64.ReverseElementBits(v2);
            v2 = AdvSimd.Xor(v0, v2);

            (var v5, var v7) = GHashMultiply(v1.AsByte(), v2.AsByte(), v16);
            v0 = GHashReduce(v5, v7, v26, vzr);

            if ((--blocks) != 0)
            {
                goto ghash_loop;
            }

            v1 = AdvSimd.ReverseElement16(v0.AsInt64()).AsByte();
            v1 = AdvSimd.Arm64.ReverseElementBits(v1);
            v1.AsInt64().CopyTo(state);
        }

        private static (Vector128<byte> Lower, Vector128<byte> Upper) GHashMultiply(Vector128<byte> a, Vector128<byte> b, Vector128<byte> a1_xor_a0)
        {
            var tmp1 = AdvSimd.ExtractVector128(b, b, 0x08);
            var result_hi = AdvSimd.PolynomialMultiplyWideningUpper(b, a);
            tmp1 = AdvSimd.Xor(tmp1, b);
            var result_lo = AdvSimd.PolynomialMultiplyWideningLower(b.GetLower(), a.GetLower());
            var tmp2 = AdvSimd.PolynomialMultiplyWideningLower(tmp1.GetLower(), a1_xor_a0.GetLower());

            var tmp4 = AdvSimd.ExtractVector128(result_lo, result_hi, 0x08);
            var tmp3 = AdvSimd.Xor(result_hi, result_lo);
            tmp2 = AdvSimd.Xor(tmp2, tmp4);
            tmp2 = AdvSimd.Xor(tmp2, tmp3);

            result_hi = AdvSimd.Insert(tmp2, 0, 1);
            result_lo = AdvSimd.Insert(tmp2, 1, 0);

            return (result_lo.AsByte(), result_hi.AsByte());
        }

        private static Vector128<byte> GHashReduce(Vector128<byte> lo, Vector128<byte> hi, Vector128<byte> p, Vector128<byte> z)
        {
            var result = AdvSimd.PolynomialMultiplyWideningUpper(hi, p);
            var t1 = AdvSimd.ExtractVector128(result, z, 8);
            hi = AdvSimd.Xor(hi, t1);
            t1 = AdvSimd.ExtractVector128(z, result, 8);
            lo = AdvSimd.Xor(lo, t1);
            result = AdvSimd.PolynomialMultiplyWideningLower(hi, p);
            result = AdvSimd.Xor(lo, result);
            return result;
        }
    }
}

#endif