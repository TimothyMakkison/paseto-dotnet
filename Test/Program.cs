using System;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;
using Paseto;
using Paseto.Builder;
using Paseto.Cryptography.Key;
using Paseto.Cryptography;
using System.Security.Cryptography;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Buffers.Binary;
using Org.BouncyCastle.Asn1.X500;

BenchmarkRunner.Run<BenchEncoding>();
//var b = new Benchmark();
//b.Sign();

[MemoryDiagnoser]
public class BenchLE64
{
    [Benchmark]
    public byte[] StackAllocPaseto()
    {
        var n = 13241234;
        var up = ~~(n / 0xffffffff);
        var dn = (n % 0xffffffff) - up;

        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(buf[4..], (uint)up);
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)dn);
        return buf.ToArray();
    }
    [Benchmark]
    public byte[] ArrayPaseto()
    {
        var n = 13241234;
        var up = ~~(n / 0xffffffff);
        var dn = (n % 0xffffffff) - up;

        var buf = new byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(buf[4..], (uint)up);
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)dn);

        return buf;
    }
    [Benchmark]
    public byte[] AsSpanPaseto()
    {
        var n = 13241234;
        var up = ~~(n / 0xffffffff);
        var dn = (n % 0xffffffff) - up;

        var buf = new byte[8].AsSpan();
        BinaryPrimitives.WriteUInt32LittleEndian(buf[4..], (uint)up);
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)dn);

        return buf.ToArray();
    }
}


[MemoryDiagnoser]
public class Benchmark
{
    private PasetoAsymmetricKeyPair _key;
    private byte[] _bytes;
    public Benchmark()
    {
        _bytes = new byte[64];
        _key = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Public)
                               .GenerateAsymmetricKeyPair(new byte[32]);
    }

    [Benchmark]
    public string Sign()
    {
        var token = new PasetoBuilder().Use(ProtocolVersion.V2, Purpose.Public)
                               .WithKey(_key.SecretKey)
                               .AddClaim("data", "this is a secret message")
                               .Issuer("https://github.com/daviddesmet/paseto-dotnet")
                               .Subject(Guid.NewGuid().ToString())
                               .Audience("https://paseto.io")
                               .NotBefore(DateTime.UtcNow)
                               .IssuedAt(DateTime.UtcNow)
                               .Expiration(DateTime.UtcNow.AddHours(1))
                               .TokenIdentifier("123456ABCD")
                               .AddFooter("arbitrary-string-that-isn't-json")
                               .Encode();
        return token;
    }

    //[Benchmark]
    //public byte[] Syst()
    //{
    //    using var sha = SHA512.Create();
    //    return sha.ComputeHash(_bytes);
    //}

    //[Benchmark]
    //public byte[] Paseto()
    //{
    //    var sha = new Sha512(); ;
    //    sha.Update(_bytes);
    //    return sha.Finish();
    //}
}

[MemoryDiagnoser]
public class BenchEncoding
{
    private const char OnePadChar = '=';
    private const string TwoPadChar = "==";
    private const char Char62 = '+';
    private const char Char63 = '/';
    private const char UrlChar62 = '-';
    private const char UrlChar63 = '_';

    private static readonly char[] OnePads = { OnePadChar };

    private static readonly byte[] Bytes = new byte[5010];
    public BenchEncoding()
    {
        Random rnd = new Random(0);
        rnd.NextBytes(Bytes);
    }

    [Benchmark]
    public string SpanEncode()
    {

        var input = Bytes;
        Span<char> span = Convert.ToBase64String(input).ToCharArray();

        if (true)
        {
            var j = span.Length - 1;
            while (span[j] == OnePadChar && j>0)
            {
                j--;
            }

            span = span.Slice(0, j+1);
        }

        for (int i = 0; i < span.Length; i++)
        {
            span[i] = span[i] switch
            {
                Char62 => UrlChar62,
                Char63 => UrlChar63,
                _ => span[i],
            };
        }

        var s = new string(span);

        return s;
    }

    [Benchmark]
    public string SlowStringEcode()
    {
        var input = Bytes;

        var a = Convert.ToBase64String(input);
        var b = a.Replace(Char62, UrlChar62);
        var encoded = b.Replace(Char63, UrlChar63);
        if (true)
            encoded = encoded.TrimEnd(OnePads);

        return encoded;
    }

    [Benchmark]
    public string StringCreateEncode()
    {
        var input = Bytes;
        var c = Convert.ToBase64String(input);

        var j = c.Length - 1;
        while (c[j] == OnePadChar && j>0)
        {
            j--;
        }

        return String.Create(j+1, c, (span,c) =>
        {
            c[..span.Length].CopyTo(span);

            for (int i = 0; i < span.Length; i++)
            {
                span[i] = span[i] switch
                {
                    Char62 => UrlChar62,
                    Char63 => UrlChar63,
                    _ => span[i],
                };
            }
        });
        
    }

    [Benchmark]
    public string StringEcode()
    {
        var input = Bytes;

        var encoded = Convert.ToBase64String(input).Replace(Char62, UrlChar62).Replace(Char63, UrlChar63);
        if (true)
            encoded = encoded.TrimEnd(OnePads);

        return encoded;
    }
}

[MemoryDiagnoser]
[SimpleJob(BenchmarkDotNet.Jobs.RuntimeMoniker.Net60)]
public class BenchPAE
{
    public static byte[][] Short => new byte[][] { new byte[15], new byte[303], new byte[40] };
    //public byte[][] Long => new byte[][] { new byte[] {10,2 } };

    public BenchPAE()
    {
        var rnd = new Random(1);
        rnd.NextBytes(Short[0]);
        rnd.NextBytes(Short[1]);
        rnd.NextBytes(Short[2]);
    }
    [Benchmark]
    public byte[] ByteArray()
    {
        var pieces = Short;

        var length = (pieces.Length + 1) * 8;

        for (var i = 0; i < pieces.Length; i++)
        {
            length += pieces[i].Length;
        }

        var accumulator = new byte[length];
        SpanExtensions.Copy(LE64(pieces.Length), 0, accumulator, 0, 8);

        var ind = 8;
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            SpanExtensions.Copy(len, 0, accumulator, ind, 8);
            SpanExtensions.Copy(piece, 0, accumulator, ind+8, piece.Length);

            ind += 8+piece.Length;
        }
        return accumulator;
    }
    [Benchmark]
    public byte[] InlineByteArray()
    {
        var pieces = Short;

        var length = (pieces.Length + 1) * 8;

        for (var i = 0; i < pieces.Length; i++)
        {
            length += pieces[i].Length;
        }

        var accumulator = new byte[length];
        var s = accumulator.AsSpan();
        LE64(pieces.Length).CopyTo(s);

        var ind = 8;
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            len.AsSpan().CopyTo(s.Slice(ind));
            piece.CopyTo(s.Slice(ind+8));

            ind += 8+piece.Length;
        }
        return accumulator;
    }

    [Benchmark]
    public byte[] SpanArray()
    {
        var pieces = Short;

        var headerSize = (pieces.Length + 1) * 8;
        var aggArraySize = 0;

        for (var i = 0; i < pieces.Length; i++)
        {
            aggArraySize += pieces[i].Length;
        }

        var accumulator = new byte[headerSize + aggArraySize].AsSpan();
        SpanExtensions.Copy(LE64(pieces.Length), 0, accumulator, 0, 8);

        var ind = 8;
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            SpanExtensions.Copy(len, 0, accumulator, ind, 8);
            SpanExtensions.Copy(piece, 0, accumulator, ind+8, piece.Length);

            ind += 8+piece.Length;
        }
        return accumulator.ToArray();
    }

    [Benchmark]
    public byte[] StackallocArray()
    {
        var pieces = Short;

        var length = (pieces.Length + 1) * 8;

        for (var i = 0; i < pieces.Length; i++)
        {
            length += pieces[i].Length;
        }

        Span<byte> accumulator = stackalloc byte[length];
        SpanExtensions.Copy(LE64(pieces.Length), 0, accumulator, 0, 8);

        var index = 8;
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            len.CopyTo(accumulator.Slice(index));
            piece.CopyTo(accumulator.Slice(index+8));

            index += 8 + piece.Length;
        }
        return accumulator.ToArray();
    }

    [Benchmark]
    public byte[] ListEncode()
    {
        var pieces = Short;
        var accumulator = new List<byte>(LE64(pieces.Length));
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            accumulator.AddRange(len);
            accumulator.AddRange(piece);
        }
        return accumulator.ToArray();
    }

    [Benchmark]
    public byte[] ArrayEncode()
    {
        var pieces = Short;

        var accumulator = LE64(pieces.Length);
        foreach (var piece in pieces)
        {
            var len = LE64(piece.Length);
            accumulator = accumulator.Concat(len).Concat(piece).ToArray();
        }
        return accumulator;
    }

    private static byte[] LE64(int n)
    {
        var up = ~~(n / 0xffffffff);
        var dn = (n % 0xffffffff) - up;

        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteUInt32LittleEndian(buf[4..], (uint)up);
        BinaryPrimitives.WriteUInt32LittleEndian(buf, (uint)dn);

        return buf.ToArray();
    }
}

internal static class SpanExtensions
{
    public static void Copy(ReadOnlySpan<byte> sourceSpan, int sourceIndex, Span<byte> destinationSpan, int destinationIndex, int length) => sourceSpan.Slice(sourceIndex, length).CopyTo(destinationSpan.Slice(destinationIndex, length));
}

// Bench span version and default version
// Use varying lengths
// 
//[MemoryDiagnoser]
//public class BenchEncode
//{
//    private const char OnePadChar = '=';
//    private const string TwoPadChar = "==";
//    private const char Char62 = '+';
//    private const char Char63 = '/';
//    private const char UrlChar62 = '-';
//    private const char UrlChar63 = '_';
//    public BenchEncode()
//    {

//    }

//    [Params("My Short input","Morbi a metus. Phasellus enim erat, vestibulum vel, aliquam a, posuere eu, velit. Nullam sapien sem, ornare ac, nonummy non, lobortis a, enim. Nunc tincidunt ante vitae massa. Duis ante orci, molestie vitae, vehicula venenatis, tincidunt ac, pede. Nulla accumsan, elit")]
//    public byte[] Input { get; set; }

//    [Benchmark]
//    public string PasetoEncode()
//    {
//        var input = Input;
//        var encoded = Convert.ToBase64String(input).Replace(Char62, UrlChar62).Replace(Char63, UrlChar63);
//        //if (policy == PaddingPolicy.Discard)
//        //    encoded = encoded.TrimEnd(OnePads);

//        return encoded;
//    }

//    // Byte 3 -> 4 String
//    // 0 -> 0
//    // 1 -> 2
//    // 2 -> 3
//    // 3 -> 4
//    [Benchmark]
//    public string SpanEncode()
//    {
//        var len = Input.Length / 3 * 4;
//        var r = Input.Length % 3;
//        len += r > 0 ? r+1 : 0;

//        var span = new byte[len];
//        var map = EncodingMap;

//        for (int j = 0; j < len / 3; j++)
//        {
//            uint t0 = Input[j*3];
//            uint t1 = Input[j*3+1];
//            uint t2 = Input[j*3+2];

//            uint i = (t0 << 16) | (t1 << 8) | t2;

//            var sOff = j * 4;
//            span[sOff] = EncodingMap[(int)(i >> 18)];
//            span[sOff] = EncodingMap[(int)((i >> 12) & 0x3F)];
//            span[sOff] = EncodingMap[(int)((i >> 6) & 0x3F)];
//            span[sOff] = EncodingMap[(int)(i & 0x3F)];
//        }

//        unsafe
//        {
//            fixed (char* ptr = &MemoryMarshal.GetReference(span))
//                return new string(ptr, 0, written);
//        }
//    }

//    internal static ReadOnlySpan<byte> EncodingMap
//    {
//        [MethodImpl(MethodImplOptions.AggressiveInlining)]
//        get
//        {
//            ReadOnlySpan<byte> map = new byte[64 + 1] {
//                    0,      // https://github.com/dotnet/coreclr/issues/23194
//                    65, 66, 67, 68, 69, 70, 71, 72,         //A..H
//                    73, 74, 75, 76, 77, 78, 79, 80,         //I..P
//                    81, 82, 83, 84, 85, 86, 87, 88,         //Q..X
//                    89, 90, 97, 98, 99, 100, 101, 102,      //Y..Z, a..f
//                    103, 104, 105, 106, 107, 108, 109, 110, //g..n
//                    111, 112, 113, 114, 115, 116, 117, 118, //o..v
//                    119, 120, 121, 122, 48, 49, 50, 51,     //w..z, 0..3
//                    52, 53, 54, 55, 56, 57, 45, 95          //4..9, -, _
//                };

//            // Slicing is necessary to "unlink" the ref and let the JIT keep it in a register
//            return map.Slice(1);
//        }
//    }
//}
