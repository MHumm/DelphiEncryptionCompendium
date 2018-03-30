{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2018 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
  Copyright (c) 2008 - 2012 Frederik A. Winkelsdorf (winkelsdorf [at] gmail [dot] com)
  Copyright (c) 1999 - 2008 Hagen Reddmann (HaReddmann [at] T-Online [dot] de)
  All rights reserved.

                               *** License ***

  This file is part of the Delphi Encryption Compendium (DEC). The DEC is free
  software being offered under a dual licensing scheme: BSD or MPL 1.1.

  The contents of this file are subject to the Mozilla Public License (MPL)
  Version 1.1 (the "License"); you may not use this file except in compliance
  with the License. You may obtain a copy of the License at
  http://www.mozilla.org/MPL/

  Alternatively, you may redistribute it and/or modify it under the terms of
  the following Berkeley Software Distribution (BSD) license:

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice,
       this list of conditions and the following disclaimer.
    2. Redistributions in binary form must reproduce the above copyright
       notice, this list of conditions and the following disclaimer in the
       documentation and/or other materials provided with the distribution.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
  THE POSSIBILITY OF SUCH DAMAGE.

                        *** Export/Import Controls ***

  This is cryptographic software. Even if it is created, maintained and
  distributed from liberal countries in Europe (where it is legal to do this),
  it falls under certain export/import and/or use restrictions in some other
  parts of the world.

  PLEASE REMEMBER THAT EXPORT/IMPORT AND/OR USE OF STRONG CRYPTOGRAPHY
  SOFTWARE OR EVEN JUST COMMUNICATING TECHNICAL DETAILS ABOUT CRYPTOGRAPHY
  SOFTWARE IS ILLEGAL IN SOME PARTS OF THE WORLD. SO, WHEN YOU IMPORT THIS
  PACKAGE TO YOUR COUNTRY, RE-DISTRIBUTE IT FROM THERE OR EVEN JUST EMAIL
  TECHNICAL SUGGESTIONS OR EVEN SOURCE PATCHES TO THE AUTHOR OR OTHER PEOPLE
  YOU ARE STRONGLY ADVISED TO PAY CLOSE ATTENTION TO ANY EXPORT/IMPORT AND/OR
  USE LAWS WHICH APPLY TO YOU. THE AUTHORS OF THE DEC ARE NOT LIABLE FOR ANY
  VIOLATIONS YOU MAKE HERE. SO BE CAREFUL, IT IS YOUR RESPONSIBILITY.

*****************************************************************************}

{$M+} // DUnitX would add it anyway
unit TestDECUtil;

interface

// Needs to be included before any other statements
{$I defines.inc}

uses
  {$IFNDEF DUnitX}
  TestFramework,
  {$ENDIF}
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ENDIF}
  SysUtils, Classes, DECUtil;

type
  TTestBitTwiddling = class(TTestCase)
  published
    procedure ReverseBits;
    procedure SwapBytes;
    procedure SwapLong;
    procedure SwapLongBuffer;
    procedure SwapInt64;
    procedure SwapInt64Buffer;
    procedure XORBuffers;
  end;

  TTestBufferProtection = class(TTestCase)
  published
    procedure ProtectBuffer;
    procedure ProtectStream;
    procedure ProtectStreamPartial;
    procedure ProtectBytes;
    procedure ProtectString;
    procedure ProtectStringAnsi;
    procedure ProtectStringWide;
    procedure BytesToRawString;
    procedure BytesToRawStringEmpty;
  end;

implementation

type
  TestRecCardinal = record
    Input: Cardinal;
    Result: Cardinal;
  end;

  TestRecInt64 = record
    Input : Int64;
    Result: Int64;
  end;

procedure TTestBitTwiddling.ReverseBits;
const
  ReverseBitArray: array[0..4] of TestRecCardinal = (
    (Input: 0;           Result: 0),
    (Input: 256;         Result: 8388608),
    (Input: 1024;        Result: 2097152),
    (Input: 65536;       Result: 32768),
    (Input: 4294967295;  Result: 4294967295)
  );
var
  i: Integer;
begin
  for i := 0 to Length(ReverseBitArray) - 1 do
  begin
    CheckEquals(ReverseBitArray[i].Result, DECUtil.ReverseBits(ReverseBitArray[i].Input));
  end;
end;

procedure TTestBitTwiddling.SwapBytes;
const
  Input: AnsiString  = '0123456789';
  Output: AnsiString = '9876543210';
var
  s: AnsiString;
  c: Cardinal;
begin
  s := Input;
  DECUtil.SwapBytes(s[Low(s)], Length(s));
  CheckEquals(Output, s);

  DECUtil.SwapBytes(s[Low(s)], Length(s));
  CheckEquals(Input, s);

  c := 123456789;
  DECUtil.SwapBytes(c, SizeOf(UInt32));
  CheckEquals(365779719, c);

  c := High(Cardinal);
  DECUtil.SwapBytes(c, SizeOf(UInt32));
  CheckEquals(4294967295, c);
end;

procedure TTestBitTwiddling.SwapLong;
const
  SwapLongArray: array[0..4] of TestRecCardinal = (
    (Input: 0;           Result: 0),
    (Input: 256;         Result: 65536),
    (Input: 1024;        Result: 262144),
    (Input: 65536;       Result: 256),
    (Input: 4294967295;  Result: 4294967295)
  );
var
  i: Integer;
begin
  for i := 0 to Length(SwapLongArray) - 1 do
    CheckEquals(SwapLongArray[i].Result, DECUtil.SwapUInt32(SwapLongArray[i].Input));
end;

procedure TTestBitTwiddling.SwapLongBuffer;
const
  SwapLongArray: array[0..4] of TestRecCardinal = (
    (Input: 0;           Result: 0),
    (Input: 256;         Result: 65536),
    (Input: 1024;        Result: 262144),
    (Input: 65536;       Result: 256),
    (Input: 4294967295;  Result: 4294967295)
  );

var
  SrcBuf  : array[0..length(SwapLongArray)] of UInt32;
  DestBuf : array[0..length(SwapLongArray)] of UInt32;
  i       : Integer;
begin
  for i := Low(SwapLongArray) to High(SwapLongArray) do
    SrcBuf[i] := SwapLongArray[i].Input;

  DECUtil.SwapUInt32Buffer(SrcBuf, DestBuf, Length(SrcBuf));

  for i := Low(SwapLongArray) to High(SwapLongArray) do
    CheckEquals(SwapLongArray[i].Result, DestBuf[i]);
end;

procedure TTestBitTwiddling.SwapInt64;
const
  // Intel CPU is Little Endian
  SwapInt64Array: array[0..6] of TestRecInt64 = (
    (Input: 0;           Result: 0),
    (Input: 1;           Result: 72057594037927936),  // 2^56
    (Input: 2;           Result: 144115188075855872), // 2^57
    (Input: 256;         Result: 281474976710656),    // 2^48
    (Input: 65536;       Result: 1099511627776),      // 2^40
    (Input: 16777216;    Result: 4294967296),         // 2^32
    (Input: -1;          Result: -1)
  );

var
  i : Integer;
begin
  for i := Low(SwapInt64Array) to High(SwapInt64Array) do
    CheckEquals(SwapInt64Array[i].Result, DECUtil.SwapInt64(SwapInt64Array[i].Input));
end;

procedure TTestBitTwiddling.SwapInt64Buffer;
const
  // Intel CPU is Little Endian
  SwapInt64Array: array[0..6] of TestRecInt64 = (
    (Input: 0;           Result: 0),
    (Input: 1;           Result: 72057594037927936),  // 2^56
    (Input: 2;           Result: 144115188075855872), // 2^57
    (Input: 256;         Result: 281474976710656),    // 2^48
    (Input: 65536;       Result: 1099511627776),      // 2^40
    (Input: 16777216;    Result: 4294967296),         // 2^32
    (Input: -1;          Result: -1)
  );

var
  SrcBuf  : array[0..length(SwapInt64Array)] of Int64;
  DestBuf : array[0..length(SwapInt64Array)] of Int64;
  i       : Integer;
begin
  for i := Low(SwapInt64Array) to High(SwapInt64Array) do
    SrcBuf[i] := SwapInt64Array[i].Input;

  DECUtil.SwapInt64Buffer(SrcBuf, DestBuf, Length(SrcBuf));

  for i := Low(SwapInt64Array) to High(SwapInt64Array) do
    CheckEquals(SwapInt64Array[i].Result, DestBuf[i]);
end;

procedure TTestBitTwiddling.XORBuffers;
type
  UInt32Rec = packed record
    case Integer of
      0: (UInt32: UInt32);
      1: (Bytes: array [0..3] of Byte);
  end;

var
  LBuf, RBuf : TBytes;
  DestBuf    : TBytes;
  CheckBuf   :UInt32Rec;
  i          : Integer;
begin
  SetLength(LBuf, 4);
  SetLength(RBuf, 4);
  SetLength(DestBuf, 4);

  for i := 0 to 3 do
  begin
    LBuf[i] := i;
    RBuf[i] := i;
  end;

  DECUtil.XORBuffers(LBuf[0], RBuf[0], Length(LBuf), DestBuf[0]);

  for i := Low(DestBuf) to High(DestBuf) do
    CheckBuf.Bytes[i] := DestBuf[i];

  CheckEquals(0, CheckBuf.UInt32);

  SetLength(LBuf, 4);
  SetLength(RBuf, 4);
  SetLength(DestBuf, 4);

  for i := 0 to 3 do
  begin
    LBuf[i] := i;
    RBuf[i] := 0;
  end;

  DECUtil.XORBuffers(LBuf[0], RBuf[0], Length(LBuf), DestBuf[0]);

  for i := Low(DestBuf) to High(DestBuf) do
    CheckBuf.Bytes[i] := DestBuf[i];

  CheckEquals(50462976, CheckBuf.UInt32);
end;

procedure TTestBufferProtection.ProtectBuffer;
var
  Buf : TBytes;
  i   : Integer;
begin
  SetLength(Buf, 12);
  for i := $40 to $40 + Length(Buf) - 1 do
    Buf[i-$40] := i;

  DECUtil.ProtectBuffer(Buf[0], Length(Buf));
  CheckEquals(#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00,
              string(DECUtil.BytesToRawString(Buf)));
end;

procedure TTestBufferProtection.ProtectStream;
var
  Stream  : TMemoryStream;
  SrcBuf  : TBytes;
  DestBuf : TBytes;
  i       : Integer;
begin
  SetLength(SrcBuf, 12);
  for i := $40 to $40 + Length(SrcBuf) - 1 do
    SrcBuf[i-$40] := i;

  SetLength(DestBuf, Length(SrcBuf));

  Stream := TMemoryStream.Create;
  try
    Stream.Write(SrcBuf[0], Length(SrcBuf));
    Stream.Position := 0;
    DECUtil.ProtectStream(Stream, Stream.Size);

    Stream.Read(DestBuf[0], Stream.Size);
    CheckEquals(#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00+#$00,
                string(DECUtil.BytesToRawString(DestBuf)));
  finally
    Stream.Free;
  end;
end;

procedure TTestBufferProtection.ProtectStreamPartial;
var
  Stream  : TMemoryStream;
  SrcBuf  : TBytes;
  DestBuf : TBytes;
  i       : Integer;
begin
  SetLength(SrcBuf, 12);
  for i := $40 to $40 + Length(SrcBuf) - 1 do
    SrcBuf[i-$40] := i;

  SetLength(DestBuf, Length(SrcBuf));

  Stream := TMemoryStream.Create;
  try
    Stream.Write(SrcBuf[0], Length(SrcBuf));
    Stream.Position := 0;
    DECUtil.ProtectStream(Stream, 2);

    Stream.Read(DestBuf[0], Stream.Size);
    CheckEquals(#$42+#$43+#$44+#$45+#$46+#$47+#$48+#$49+#$4A+#$4B+#$00+#$00,
                string(DECUtil.BytesToRawString(DestBuf)));
  finally
    Stream.Free;
  end;
end;

procedure TTestBufferProtection.ProtectBytes;
var
  Buf : TBytes;
  i   : Integer;
begin
  SetLength(Buf, 12);
  for i := $40 to $40 + Length(Buf) - 1 do
    Buf[i-$40] := i;

  DecUtil.ProtectBytes(Buf);

  CheckEquals('', string(DECUtil.BytesToRawString(Buf)));
end;

procedure TTestBufferProtection.ProtectString;
var
  s : string;
begin
  s := 'Hello';
  DECUtil.ProtectString(s);

  CheckEquals('', s);
end;

procedure TTestBufferProtection.ProtectStringAnsi;
var
  s : AnsiString;
begin
  s := 'Hello';
  DECUtil.ProtectString(s);

  CheckEquals('', string(s));
end;

procedure TTestBufferProtection.ProtectStringWide;
var
  s : WideString;
begin
  s := 'Hello';
  DECUtil.ProtectString(s);

  CheckEquals('', string(s));
end;

procedure TTestBufferProtection.BytesToRawString;
var
  Buf: TBytes;
  i  : Integer;
  result : RawByteString;
begin
  SetLength(Buf, 43);
  for i := 48 to 48 + length(Buf) - 1 do
    Buf[i-48] := i;

  result := DECUtil.BytesToRawString(Buf);

  CheckEquals('0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ',
              string(result));
end;

procedure TTestBufferProtection.BytesToRawStringEmpty;
var
  Buf: TBytes;
begin
  SetLength(Buf, 0);

  CheckEquals('', string(DECUtil.BytesToRawString(Buf)));
end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTests('DECUtil', [TTestBitTwiddling.Suite, TTestBufferProtection.Suite]);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TTestBitTwiddling);
  TDUnitX.RegisterTestFixture(TTestBufferProtection);
  {$ENDIF}
end.
