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
unit TestDECHash;

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
  DECBaseClass, DECHash, DECHashBase, Classes, SysUtils, DECUtil, DECFormatBase;

type
  /// <summary>
  ///   Contains the test data for one single test iteration
  /// </summary>
  THashTestRec = record
    /// <summary>
    ///   Data to be put in
    /// </summary>
    Input            : RawByteString;
    /// <summary>
    ///   Data to be returned from the called test method
    /// </summary>
    Output           : RawByteString;
    /// <summary>
    ///   Data to be returned from the called Unicode String test method
    /// </summary>
    OutputUTFStrTest : RawByteString;
    /// <summary>
    ///   Requested Digest Size is only being needed for the THashSapphire tests
    /// </summary>
    ReqDigSize       : Integer;
    /// <summary>
    ///   Padding Byte for the Haval Hash Tests
    /// </summary>
    PaddingByte      : Byte;
    /// <summary>
    ///   when true this tes twill run, otherwise not
    /// </summary>
    Enabled          : Boolean;
  end;

  THash_TestBase = class(TTestCase)
  strict protected
    FTestData : array of THashTestRec;

    procedure DoTestCalcBuffer(HashClass:TDECHash);
    procedure DoTestCalcBytes(HashClass:TDECHash);
    procedure DoTestCalcStream(HashClass:TDECHash);
    procedure DoTestCalcUnicodeString(HashClass:TDECHash);
    procedure DoTestCalcRawByteString(HashClass:TDECHash);
  published
  end;

  // Test methods for class THash_MD2
  TestTHash_MD2 = class(THash_TestBase)
  strict private
    FHash_MD2: THash_MD2;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcUnicodeString;
    procedure TestCalcRawByteString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;

    procedure TestKDF2;
  end;

  // Test methods for class THash_MD4
  TestTHash_MD4 = class(THash_TestBase)
  strict private
    FHash_MD4: THash_MD4;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_MD5
  TestTHash_MD5 = class(THash_TestBase)
  strict private
    FHash_MD5: THash_MD5;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_RipeMD128
  TestTHash_RipeMD128 = class(THash_TestBase)
  strict private
    FHash_RipeMD128: THash_RipeMD128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_RipeMD160
  TestTHash_RipeMD160 = class(THash_TestBase)
  strict private
    FHash_RipeMD160: THash_RipeMD160;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_RipeMD256
  TestTHash_RipeMD256 = class(THash_TestBase)
  strict private
    FHash_RipeMD256: THash_RipeMD256;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_RipeMD320
  TestTHash_RipeMD320 = class(THash_TestBase)
  strict private
    FHash_RipeMD320: THash_RipeMD320;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_SHA
  TestTHash_SHA = class(THash_TestBase)
  strict private
    FHash_SHA: THash_SHA;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_SHA256
  TestTHash_SHA256 = class(THash_TestBase)
  strict private
    FHash_SHA256: THash_SHA256;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_SHA384
  TestTHash_SHA384 = class(THash_TestBase)
  strict private
    FHash_SHA384: THash_SHA384;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_SHA512
  TestTHash_SHA512 = class(THash_TestBase)
  strict private
    FHash_SHA512: THash_SHA512;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Haval128
  TestTHash_Haval128 = class(THash_TestBase)
  strict private
    FHash_Haval128: THash_Haval128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Haval160
  TestTHash_Haval160 = class(THash_TestBase)
  strict private
    FHash_Haval160: THash_Haval160;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Haval192
  TestTHash_Haval192 = class(THash_TestBase)
  strict private
    FHash_Haval192: THash_Haval192;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Haval224
  TestTHash_Haval224 = class(THash_TestBase)
  strict private
    FHash_Haval224: THash_Haval224;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Haval256
  TestTHash_Haval256 = class(THash_TestBase)
  strict private
    FHash_Haval256: THash_Haval256;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Tiger
  TestTHash_Tiger_3Rounds = class(THash_TestBase)
  strict private
    FHash_Tiger: THash_Tiger;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestSetRounds;
    procedure TestSet2Rounds;
    procedure TestSet33Rounds;
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Tiger
  TestTHash_Tiger_4Rounds = class(THash_TestBase)
  strict private
    FHash_Tiger: THash_Tiger;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestSetRounds;
    procedure TestSet2Rounds;
    procedure TestSet33Rounds;
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Panama
  TestTHash_Panama = class(THash_TestBase)
  strict private
    FHash_Panama: THash_Panama;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
{ TODO : TestDigest raus und die üblichen TestCalcXXX rein sowie Setup ausfüllen }
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Whirlpool
  TestTHash_Whirlpool = class(THash_TestBase)
  strict private
    FHash_Whirlpool: THash_Whirlpool;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Whirlpool1
  TestTHash_Whirlpool1 = class(THash_TestBase)
  strict private
    FHash_Whirlpool1: THash_Whirlpool1;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Square
  TestTHash_Square = class(THash_TestBase)
  strict private
    FHash_Square: THash_Square;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Snefru128
  TestTHash_Snefru128 = class(THash_TestBase)
  strict private
    FHash_Snefru128: THash_Snefru128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Snefru256
  TestTHash_Snefru256 = class(THash_TestBase)
  strict private
    FHash_Snefru256: THash_Snefru256;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

  // Test methods for class THash_Sapphire
  TestTHash_Sapphire = class(THash_TestBase)
 strict private
    FHash_Sapphire: THash_Sapphire;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestCalcBuffer;
    procedure TestCalcBytes;
    procedure TestCalcStream;
    procedure TestCalcRawByteString;
    procedure TestCalcUnicodeString;
//    procedure TestCalcFile;
    procedure TestDigestSize;
    procedure TestBlockSize;
    procedure TestIsPasswordHash;
  end;

implementation

uses
  DECFormat;

procedure TestTHash_MD2.SetUp;
begin
  FHash_MD2 := THash_MD2.Create;
  SetLength(FTestData, 3);

  FTestData[ 0].Output           := '8350e5a3e24c153df2275c9f80692773';
  FTestData[ 0].OutputUTFStrTest := '8350e5a3e24c153df2275c9f80692773';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '8415570a6653a06314f09b023612a92d';
  FTestData[ 1].OutputUTFStrTest := '9d76631406e8be4ed7284613edf23fd5';
  FTestData[ 1].Input            := 'Franz jagt im komplett verwahrlosten Taxi quer durch Bayern';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'b0e27e91b84246bc4c38bc3008f00374';
  FTestData[ 2].OutputUTFStrTest := 'b2ea09572c2fcfb278afd72155bc28e7';
  FTestData[ 2].Input            := 'Frank jagt im komplett verwahrlosten Taxi quer durch Bayern';
  FTestData[ 2].Enabled          := true;
end;

procedure TestTHash_MD2.TearDown;
begin
  FHash_MD2.Free;
  FHash_MD2 := nil;
end;

procedure TestTHash_MD2.TestDigestSize;
begin
  CheckEquals(16, FHash_MD2.DigestSize);
end;

procedure TestTHash_MD2.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_MD2.IsPasswordHash);
end;

procedure TestTHash_MD2.TestKDF2;
var
  Data, Seed : TBytes;
  KDF2Res    : TBytes;
begin
{ TODO :
Test verallgemeinert aufbauen und über Testdata als Eingabe gehen.
Außerdem für jede Hash Funktion umsetzen? }
  SetLength(Data, 5);
  Data := [0, 1, 2, 3, 4];

  SetLength(Seed, 5);
  Seed := [5, 6, 7, 8, 9];

  KDF2Res := THash_MD2.KDF2(Data, Seed, 2);

  CheckEquals('380C',
              string(TFormat_HEX.Encode(KDF2Res, Length(KDF2Res))));
end;

procedure TestTHash_MD2.TestBlockSize;
begin
  CheckEquals(16, FHash_MD2.BlockSize);
end;

procedure TestTHash_MD2.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_MD2);
end;

procedure TestTHash_MD2.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_MD2);
end;

procedure TestTHash_MD2.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_MD2);
end;

procedure TestTHash_MD2.TestCalcStream;
begin
  DoTestCalcStream(FHash_MD2);
end;

procedure TestTHash_MD2.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_MD2);
end;

procedure TestTHash_MD4.SetUp;
begin
  FHash_MD4 := THash_MD4.Create;

  SetLength(FTestData, 11);

  FTestData[ 0].Output           := '31d6cfe0d16ae931b73c59d7e0c089c0';
  FTestData[ 0].OutputUTFStrTest := '31d6cfe0d16ae931b73c59d7e0c089c0';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'bde52cb31de33e46245e05fbdbd6fb24';
  FTestData[ 1].OutputUTFStrTest := '186cb09181e2c2ecaac768c47c729904';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'a448017aaf21d8525fc10ae87aa6729d';
//  FTestData[ 2].OutputUTFStrTest := ;
  FTestData[ 2].Input            := 'ab,c ';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := 'd9130a8164549fe818874806e1c7014b';
  FTestData[ 3].OutputUTFStrTest := '94a8a6cc36108b93db330de54b90bd4b';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'd79e1c308aa5bbcdeea8ed63df412da9';
//  FTestData[ 4].OutputUTFStrTest := ;
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '043f8582f241db351ce627e153e7f0e4';
//  FTestData[ 5].OutputUTFStrTest := ;
  FTestData[ 5].Input            := 'A,BCDEFGHIJKLMNOPQRS,TUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := 'e33b4ddc9c38f2199c3e7b164fcc0536';
  FTestData[ 6].OutputUTFStrTest := 'cf17b1ae2606afa964193690df7543b1';
  FTestData[ 6].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '186767a4d851893b823e6824c6efda62';
  FTestData[ 7].OutputUTFStrTest := '720710bdf5588ff54a1541168c49ffbc';
  FTestData[ 7].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'adba72c3baf834d091eb59f18d022549';
  FTestData[ 8].OutputUTFStrTest := '077ff2742a36a53d86774f01e4911f46';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := 'bbce80cc6bb65e5c6745e30d4eeca9a4';
//  FTestData[ 9].OutputUTFStrTest :=
  FTestData[ 9].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 9].Enabled          := false;

  FTestData[10].Output           := 'bbce80cc6bb65e5c6745e30d4eeca9a4';
  FTestData[10].OutputUTFStrTest := '29830de36ff8d3c23c73535ed6d1c69f';
  SetLength(FTestData[10].Input, 1000000);
  FillChar(FTestData[10].Input[low(FTestData[10].Input)], 1000000, 'a');
  FTestData[10].Enabled:= true;
end;

procedure TestTHash_MD4.TearDown;
begin
  FHash_MD4.Free;
  FHash_MD4 := nil;
end;

procedure TestTHash_MD4.TestBlockSize;
begin
  CheckEquals(64, FHash_MD4.BlockSize);
end;

procedure TestTHash_MD4.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_MD4);
end;

procedure TestTHash_MD4.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_MD4);
end;

procedure TestTHash_MD4.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_MD4);
end;

procedure TestTHash_MD4.TestCalcStream;
begin
  DoTestCalcStream(FHash_MD4);
end;

procedure TestTHash_MD4.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_MD4);
end;

procedure TestTHash_MD4.TestDigestSize;
begin
  CheckEquals(16, FHash_MD4.DigestSize);
end;

procedure TestTHash_MD4.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_MD4.IsPasswordHash);
end;

procedure TestTHash_MD5.SetUp;
begin
  FHash_MD5 := THash_MD5.Create;

  SetLength(FTestData, 11);

  FTestData[ 0].Output           := 'd41d8cd98f00b204e9800998ecf8427e';
  FTestData[ 0].OutputUTFStrTest := 'd41d8cd98f00b204e9800998ecf8427e';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '0cc175b9c0f1b6a831c399e269772661';
  FTestData[ 1].OutputUTFStrTest := '4144e195f46de78a3623da7364d04f11';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '900150983cd24fb0d6963f7d28e17f72';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := 'ab,c ';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := 'f96b697d7cb7938d525a2f31aaf161d0';
  FTestData[ 3].OutputUTFStrTest := '6f9ab83227f65f9b86c380e2c9c33031';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'c3fcd3d76192e4007dfb496cca67e13b';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'd174ab98d277d9f5a5611c2c9f419d9f';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'A,BCDEFGHIJKLMNOPQRS,TUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := '57edf4a22be3c955ac49da2e2107b67a';
  FTestData[ 6].OutputUTFStrTest := '903f43f5c1f384fc267110bf07caec04';
  FTestData[ 6].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := 'e6810238956987dec0d7bfcbcd4caab8';
  FTestData[ 7].OutputUTFStrTest := 'a36d511965e2c68794b5fbfe54d74b8c';
  FTestData[ 7].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '637d2777ed733d5d33b5bfc140f118c5';
  FTestData[ 8].OutputUTFStrTest := '3995d2a93d5df46406ef04b34d06b177';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '7707d6ae4e027c70eea2a935c2296f21';
//  FTestData[ 9].OutputUTFStrTest := '';
  FTestData[ 9].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 9].Enabled          := false;

  FTestData[10].Output           := '7707d6ae4e027c70eea2a935c2296f21';
  FTestData[10].OutputUTFStrTest := '168f7302c596180bb5372f5015098742';
  SetLength(FTestData[10].Input, 1000000);
  FillChar(FTestData[10].Input[low(FTestData[10].Input)], 1000000, 'a');
  FTestData[10].Enabled:= true;
end;

procedure TestTHash_MD5.TearDown;
begin
  FHash_MD5.Free;
  FHash_MD5 := nil;
end;

procedure TestTHash_MD5.TestBlockSize;
begin
  CheckEquals(64, FHash_MD5.BlockSize);
end;

procedure TestTHash_MD5.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_MD5);
end;

procedure TestTHash_MD5.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_MD5);
end;

procedure TestTHash_MD5.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_MD5);
end;

procedure TestTHash_MD5.TestDigestSize;
begin
  CheckEquals(16, FHash_MD5.DigestSize);
end;

procedure TestTHash_MD5.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_MD5.IsPasswordHash);
end;

procedure TestTHash_MD5.TestCalcStream;
begin
  DoTestCalcStream(FHash_MD5);
end;

procedure TestTHash_MD5.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_MD5);
end;

procedure TestTHash_RipeMD128.SetUp;
begin
  FHash_RipeMD128 := THash_RipeMD128.Create;
  SetLength(FTestData, 12);

  FTestData[ 0].Output := 'cdf26213a150dc3ecb610f18f6b38b46';
  FTestData[ 0].OutputUTFStrTest := 'cdf26213a150dc3ecb610f18f6b38b46';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '86be7afa339d0fc7cfc785e72f578d33';
  FTestData[ 1].OutputUTFStrTest := 'b7d45de39098253a3c98c2756101f5aa';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'c14a12199c66e4ba84636b0f69144c77';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := 'ab,c ';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := '9e327b3d6e523062afc1132d7df9d1b8';
  FTestData[ 3].OutputUTFStrTest := '8adb8445ef4925f7483e0b1738f3e6b3';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'fd2aa607f71dc8f510714922b371834e';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'a1aa0689d0fafa2ddc22e88b49133a06';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'abcdbcdecdefdefg,efghfghighijhijki,jkljklmklmnlmnomnopnopq';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := 'd1e959eb179c911faea4624c60c5c702';
//  FTestData[ 6].OutputUTFStrTest := '';
  FTestData[ 6].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 6].Enabled          := false;

  FTestData[ 7].Output           := '3f45ef194732c2dbb2c4a2c769795fa3';
  FTestData[ 7].OutputUTFStrTest := '48c714a46e60f21802adef5c60b5b63e';
  FTestData[ 7].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'a4137d8c40fa51152905b3747acc0ff4';
  FTestData[ 8].OutputUTFStrTest := 'd08312b9507ea0edbc38c4b1d421e0f1';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '243988f60681af64730a7ee6b5f0406b';
  FTestData[ 9].OutputUTFStrTest := 'c227947947ad2085bd35817cf94be3d3';
  FTestData[ 9].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.';
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '4a7f5723f954eba1216c9d8f6320431f';
//  FTestData[10].OutputUTFStrTest := '';
  FTestData[10].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[10].Enabled          := false;

  FTestData[11].Output           := '4a7f5723f954eba1216c9d8f6320431f';
  FTestData[11].OutputUTFStrTest := 'c8c6d2c7e48fc3788ef778426d4382e0';
  SetLength(FTestData[11].Input, 1000000);
  FillChar(FTestData[11].Input[low(FTestData[11].Input)], 1000000, 'a');
  FTestData[11].Enabled:= true;
end;

procedure TestTHash_RipeMD128.TearDown;
begin
  FHash_RipeMD128.Free;
  FHash_RipeMD128 := nil;
end;

procedure TestTHash_RipeMD128.TestBlockSize;
begin
  CheckEquals(64, FHash_RipeMD128.BlockSize);
end;

procedure TestTHash_RipeMD128.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_RipeMD128);
end;

procedure TestTHash_RipeMD128.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_RipeMD128);
end;

procedure TestTHash_RipeMD128.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_RipeMD128);
end;

procedure TestTHash_RipeMD128.TestDigestSize;
begin
  CheckEquals(16, FHash_RipeMD128.DigestSize);
end;

procedure TestTHash_RipeMD128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_RipeMD128.IsPasswordHash);
end;

procedure TestTHash_RipeMD128.TestCalcStream;
begin
  DoTestCalcStream(FHash_RipeMD128);
end;

procedure TestTHash_RipeMD128.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_RipeMD128);
end;

procedure TestTHash_RipeMD160.SetUp;
begin
  FHash_RipeMD160 := THash_RipeMD160.Create;
  SetLength(FTestData, 12);

  FTestData[ 0].Output           := '9c1185a5c5e9fc54612808977ee8f548b2258d31';
  FTestData[ 0].OutputUTFStrTest := '9c1185a5c5e9fc54612808977ee8f548b2258d31';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '0bdc9d2d256b3ee9daae347be6f4dc835a467ffe';
  FTestData[ 1].OutputUTFStrTest := '3213d398bb951aa09625539093524fa528848bd0';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '8eb208f7e05d987a9b044a8e98c6b087f15a0bfc';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := 'ab,c ';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := '5d0689ef49d2fae572b881b123a85ffa21595f36';
  FTestData[ 3].OutputUTFStrTest := '3648d57f2b151f9bd2ef3f3d8d16efa869bb7552';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'f71c27109c692c1b56bbdceb5b9d2865b3708dbc';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '12a053384a9c0c88e405a06c27dcf49ada62eb2b';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'abcdbcdecdefdefg,efghfghighijhijki,jkljklmklmnlmnomnopnopq';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := 'b0e20b6e3116640286ed3a87a5713079b21f5189';
//  FTestData[ 6].OutputUTFStrTest := '';
  FTestData[ 6].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 6].Enabled          := false;

  FTestData[ 7].Output           := '9b752e45573d4b39f4dbd3323cab82bf63326bfb';
  FTestData[ 7].OutputUTFStrTest := '5b9333be43b8900e33224375f3a22b66a4d77388';
  FTestData[ 7].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'b8c681512ad02967243bb93d181b5783eb501f2f';
  FTestData[ 8].OutputUTFStrTest := '99079db8b7532db2699a69ca200dab8eeb8be77e';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := 'e94a9d107e49e4ea81b22cfaa4075437175d383c';
  FTestData[ 9].OutputUTFStrTest := 'a9a5a0eb2c69ddb61774054cbf800256f7eb4ac9';
  FTestData[ 9].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.';
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '52783243c1697bdbe16d37f97f68f08325dc1528';
//  FTestData[10].OutputUTFStrTest := '';
  FTestData[10].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[10].Enabled          := false;

  FTestData[11].Output           := '52783243c1697bdbe16d37f97f68f08325dc1528';
  FTestData[11].OutputUTFStrTest := '98182142d06b9952b1c7568fd0d178100e61c098';
  SetLength(FTestData[11].Input, 1000000);
  FillChar(FTestData[11].Input[low(FTestData[11].Input)], 1000000, 'a');
  FTestData[11].Enabled:= true;
end;

procedure TestTHash_RipeMD160.TearDown;
begin
  FHash_RipeMD160.Free;
  FHash_RipeMD160 := nil;
end;

procedure TestTHash_RipeMD160.TestDigestSize;
begin
  CheckEquals(20, FHash_RipeMD160.DigestSize);
end;

procedure TestTHash_RipeMD160.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_RipeMD160.IsPasswordHash);
end;

procedure TestTHash_RipeMD160.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_RipeMD160);
end;

procedure TestTHash_RipeMD160.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_RipeMD160);
end;

procedure TestTHash_RipeMD160.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_RipeMD160);
end;

procedure TestTHash_RipeMD160.TestCalcStream;
begin
  DoTestCalcStream(FHash_RipeMD160);
end;

procedure TestTHash_RipeMD160.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_RipeMD160);
end;

procedure TestTHash_RipeMD256.SetUp;
begin
  FHash_RipeMD256 := THash_RipeMD256.Create;
  SetLength(FTestData, 12);

  FTestData[ 0].Output           := '02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d';
  FTestData[ 0].OutputUTFStrTest := '02ba4c4e5f8ecd1877fc52d64d30e37a2d9774fb1e5d026380ae0168e3c5522d';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'f9333e45d857f5d90a91bab70a1eba0cfb1be4b0783c9acfcd883a9134692925';
  FTestData[ 1].OutputUTFStrTest := '9085ecd33f28d345d80830edb9bc9dbdf864810e51538db16b14f229fcce02c2';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := 'ab,c ';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := '87e971759a1ce47a514d5c914c392c9018c7c46bc14465554afcdf54a5070c0e';
  FTestData[ 3].OutputUTFStrTest := '8456b94a8564fca0356765e9e3e0ccda4af6cd486e65ce1259559143c44ba0ea';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '649d3034751ea216776bf9a18acc81bc7896118a5197968782dd1fd97d8d5133';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '3843045583aac6c8c8d9128573e7a9809afb2a0f34ccc36ea9e72f16f6368e3f';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'abcdbcdecdefdefg,efghfghighijhijki,jkljklmklmnlmnomnopnopq';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := '5740a408ac16b720b84424ae931cbb1fe363d1d0bf4017f1a89f7ea6de77a0b8';
//  FTestData[ 6].OutputUTFStrTest := '';
  FTestData[ 6].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 6].Enabled          := false;

  FTestData[ 7].Output           := '06fdcc7a409548aaf91368c06a6275b553e3f099bf0ea4edfd6778df89a890dd';
  FTestData[ 7].OutputUTFStrTest := '67e959944ad20f439af5cffa4893b5913536bba2e151b7c5bd01da6707fd331c';
  FTestData[ 7].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'ce2a12e4361b03bf914ce35267628a9f26d54ed82b764c903958f29e652e0f5d';
  FTestData[ 8].OutputUTFStrTest := 'fc0f03e8f9666aa901ddb32482eef939b1abc86d311439ed022b4ece5194363c';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '5b622dfcf325aa4476bcdeff971f961120a19bf7642b85cbdd422f46d7c7bad8';
  FTestData[ 9].OutputUTFStrTest := '3015a97978ad2824ab545aabc411f78b4b6e44acb23a865af696ef5777f7703a';
  FTestData[ 9].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.';
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := 'ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978';
//  FTestData[10].OutputUTFStrTest := '';
  FTestData[10].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[10].Enabled          := false;

  FTestData[11].Output           := 'ac953744e10e31514c150d4d8d7b677342e33399788296e43ae4850ce4f97978';
  FTestData[11].OutputUTFStrTest := 'bcda054f27f32fedeb8374ee93d01fbc0783c30b9e71cc3e2a463265eac08f76';
  SetLength(FTestData[11].Input, 1000000);
  FillChar(FTestData[11].Input[low(FTestData[11].Input)], 1000000, 'a');
  FTestData[11].Enabled:= true;
end;

procedure TestTHash_RipeMD256.TearDown;
begin
  FHash_RipeMD256.Free;
  FHash_RipeMD256 := nil;
end;

procedure TestTHash_RipeMD256.TestDigestSize;
begin
  CheckEquals(32, FHash_RipeMD256.DigestSize);
end;

procedure TestTHash_RipeMD256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_RipeMD256.IsPasswordHash);
end;

procedure TestTHash_RipeMD256.TestCalcBuffer;
begin
 DoTestCalcBuffer(FHash_RipeMD256);
end;

procedure TestTHash_RipeMD256.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_RipeMD256);
end;

procedure TestTHash_RipeMD256.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_RipeMD256);
end;

procedure TestTHash_RipeMD256.TestCalcStream;
begin
  DoTestCalcStream(FHash_RipeMD256);
end;

procedure TestTHash_RipeMD256.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_RipeMD256);
end;

procedure TestTHash_RipeMD320.SetUp;
begin
  FHash_RipeMD320 := THash_RipeMD320.Create;
  SetLength(FTestData, 12);

  FTestData[ 0].Output           := '22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8';
  FTestData[ 0].OutputUTFStrTest := '22d65d5661536cdc75c1fdf5c6de7b41b9f27325ebc61e8557177d705a0ec880151c3a32a00899b8';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'ce78850638f92658a5a585097579926dda667a5716562cfcf6fbe77f63542f99b04705d6970dff5d';
  FTestData[ 1].OutputUTFStrTest := 'becac9657471217026a3e463c4e4198d0a35a628d5b33ea9ce3bfe2e1ec03c8e48d4c71bac843224';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := 'ab,c ';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := '3a8e28502ed45d422f68844f9dd316e7b98533fa3f2a91d29f84d425c88d6b4eff727df66a7c0197';
  FTestData[ 3].OutputUTFStrTest := 'f18db73fd25af066beeb55389f10f21b0598075bc2febd0fb30f30293e4f08e8d4af496d38103f83';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'cabdb1810b92470a2093aa6bce05952c28348cf43ff60841975166bb40ed234004b8824463e6b009';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'd034a7950cf722021ba4b84df769a5de2060e259df4c9bb4a4268c0e935bbc7470a969c9d072a1ac';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'abcdbcdecdefdefg,efghfghighijhijki,jkljklmklmnlmnomnopnopq';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := 'ed544940c86d67f250d232c30b7b3e5770e0c60c8cb9a4cafe3b11388af9920e1b99230b843c86a4';
//  FTestData[ 6].OutputUTFStrTest := '';
  FTestData[ 6].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 6].Enabled          := false;

  FTestData[ 7].Output           := '557888af5f6d8ed62ab66945c6d2a0a47ecd5341e915eb8fea1d0524955f825dc717e4a008ab2d42';
  FTestData[ 7].OutputUTFStrTest := '2de7b865e6692c84c0f23116e609fc99b5717a2c38028e45cdb00cbd5df70fcac63f23aa6493a3a3';
  FTestData[ 7].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '83254b7c45b10b0f1c7cd9d6bdf1c318d4e807731b7ce21b348ac0ee17e4ee7feb1f49fc3aea7d16';
  FTestData[ 8].OutputUTFStrTest := '32c9e60055988f4d00284a9a1e6c0d27eb10fc5429dfb2a168fc6016b32759c442586c566f30d941';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 119 bytes';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '77d7e20be0672bc74ed1cb4d9f56cf455c5e86a045c18db84e2d7bba53b21788575d6d7baa3d3469';
  FTestData[ 9].OutputUTFStrTest := 'df1d29aec8620e470c45cf77852c7b917877c80d2f63a279b41cc0d65fc5c93c5bd35c08cf08db91';
  FTestData[ 9].Input            := 'This test vector intended to detect last zeroized block necessity decision error. This block has total length 120 bytes.';
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := 'bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66';
//  FTestData[10].OutputUTFStrTest := '';
  FTestData[10].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[10].Enabled          := false;

  FTestData[11].Output           := 'bdee37f4371e20646b8b0d862dda16292ae36f40965e8c8509e63d1dbddecc503e2b63eb9245bb66';
  FTestData[11].OutputUTFStrTest := '532260a4e62a359a9d1561a1e6cfd1f6988447a3ef4f810a252f69483e4ad5d7f95fc1609d29bb1a';
  SetLength(FTestData[11].Input, 1000000);
  FillChar(FTestData[11].Input[low(FTestData[11].Input)], 1000000, 'a');
  FTestData[11].Enabled:= true;
end;

procedure TestTHash_RipeMD320.TearDown;
begin
  FHash_RipeMD320.Free;
  FHash_RipeMD320 := nil;
end;

procedure TestTHash_RipeMD320.TestDigestSize;
begin
  CheckEquals(40, FHash_RipeMD320.DigestSize);
end;

procedure TestTHash_RipeMD320.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_RipeMD320.IsPasswordHash);
end;

procedure TestTHash_RipeMD320.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_RipeMD320);
end;

procedure TestTHash_RipeMD320.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_RipeMD320);
end;

procedure TestTHash_RipeMD320.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_RipeMD320);
end;

procedure TestTHash_RipeMD320.TestCalcStream;
begin
  DoTestCalcStream(FHash_RipeMD320);
end;

procedure TestTHash_RipeMD320.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_RipeMD320);
end;

procedure TestTHash_SHA.SetUp;
begin
  FHash_SHA := THash_SHA.Create;
  SetLength(FTestData, 6);

  FTestData[ 0].Output           := '0164b8a914cd2a5e74c4f7ff082c4d97f1edf880';
  FTestData[ 0].OutputUTFStrTest := 'e286e14cff397cd7e37f755e00af6a8e1b00bc55';
  FTestData[ 0].Input            := 'abc';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'd2516ee1acfa5baf33dfc1c471e438449ef134c8';
  FTestData[ 1].OutputUTFStrTest := '97163d17d936aa26b97bfad5d8ae1e328e29c532';
  FTestData[ 1].Input            := 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'f79e92290e9f519a62467812ea56920850354796';
  FTestData[ 2].OutputUTFStrTest := '53f1df401054ccfa66250ace1454b34d55059e3c';
  FTestData[ 2].Input            := 'This test vector intended to detect last zeroized block ' +
                                   'necessity decision error. This block has total length 119 bytes';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'e644dc674505c8260e58e32f6b8bcf565b2fafc4';
  FTestData[ 3].OutputUTFStrTest := '29a30604bfbd1c23545fd02faf4c6bbce9947377';
  FTestData[ 3].Input            := 'This test vector intended to detect last zeroized block ' +
                                   'necessity decision error. This block has total length 120 bytes.';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '3232affa48628a26653b5aaa44541fd90d690603';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '3232affa48628a26653b5aaa44541fd90d690603';
  FTestData[ 5].OutputUTFStrTest := '209d48020a6dff914d1503e2a760d4ef4ad4c8fe';
  SetLength(FTestData[ 5].Input, 1000000);
  FillChar(FTestData[ 5].Input[low(FTestData[ 5].Input)], 1000000, 'a');
  FTestData[ 5].Enabled:= true;
end;

procedure TestTHash_SHA.TearDown;
begin
  FHash_SHA.Free;
  FHash_SHA := nil;
end;

procedure TestTHash_SHA.TestDigestSize;
begin
  CheckEquals(20, FHash_SHA.DigestSize);
end;

procedure TestTHash_SHA.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_SHA.IsPasswordHash);
end;

procedure TestTHash_SHA.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_SHA);
end;

procedure TestTHash_SHA.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_SHA);
end;

procedure TestTHash_SHA.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_SHA);
end;

procedure TestTHash_SHA.TestCalcStream;
begin
  DoTestCalcStream(FHash_SHA);
end;

procedure TestTHash_SHA.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_SHA);
end;

procedure TestTHash_SHA256.SetUp;
begin
  FHash_SHA256 := THash_SHA256.Create;
  SetLength(FTestData, 4);

  FTestData[ 0].Output           := 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
//  FTestData[ 0].OutputUTFStrTest := '';
  FTestData[ 0].Input            := 'ab,c';
  FTestData[ 0].Enabled          := false;

  FTestData[ 1].Output           := '248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1';
//  FTestData[ 1].OutputUTFStrTest := '';
  FTestData[ 1].Input            := 'abcdbcdecdefdef,gefghfghighijhijki,jkljklmklmnlmnomnopnop,q';
  FTestData[ 1].Enabled          := false;

  FTestData[ 2].Output           := '85c0f2421bdffd1dc9568cd815175fe286e5c18a4c4e0308114f534442c6dc3c';
  FTestData[ 2].OutputUTFStrTest := 'c4ccadb4452fd1e52ca9e90e4447a2f093b4bf2acd5a1e2293ef622e0a166b53';
  FTestData[ 2].Input            := 'This test vector intended to detect last zeroized block ' +
                                   'necessity decision error. This block has total length 119 bytes';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'c8a0bcda5fec642e44488fd7b782821d478ef17e651eaec0e43f9036388340bb';
  FTestData[ 3].OutputUTFStrTest := '2f8aa82881b1140af41e95bf96ded6d034654492007b7302e1bd9231ce99bdf3';
  FTestData[ 3].Input            := 'This test vector intended to detect last zeroized block ' +
                                   'necessity decision error. This block has total length 120 bytes.';
  FTestData[ 3].Enabled          := true;
end;

procedure TestTHash_SHA256.TearDown;
begin
  FHash_SHA256.Free;
  FHash_SHA256 := nil;
end;

procedure TestTHash_SHA256.TestDigestSize;
begin
  CheckEquals(32, FHash_SHA256.DigestSize);
end;

procedure TestTHash_SHA256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_SHA256.IsPasswordHash);
end;

procedure TestTHash_SHA256.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_SHA256);
end;

procedure TestTHash_SHA256.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_SHA256);
end;

procedure TestTHash_SHA256.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_SHA256);
end;

procedure TestTHash_SHA256.TestCalcStream;
begin
  DoTestCalcStream(FHash_SHA256);
end;

procedure TestTHash_SHA256.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_SHA256);
end;

procedure TestTHash_SHA384.SetUp;
begin
  FHash_SHA384 := THash_SHA384.Create;
  SetLength(FTestData, 4);

  FTestData[ 0].Output           := 'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8' +
                                    'b605a43ff5bed8086072ba1e7cc2358baeca134c825a7';
  FTestData[ 0].OutputUTFStrTest := '9b7ce7c7af46e400a37c8099cb4bbb5d0408061dd74cdb5dac7' +
                                    '661bed1e53724bd07f299e265f400802a48d2e0b2092c';
  FTestData[ 0].Input            := 'abc';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '09330c33f71147e83d192fc782cd1b4753111b173b3b05d22fa' +
                                    '08086e3b0f712fcc7c71a557e2db966c3e9fa91746039';
//  FTestData[ 1].OutputUTFStrTest := '';
  FTestData[ 1].Input            := 'abcdefghbcdefghicdefghijdefghij,kefghijklfghijklmgh' +
                                    'ijklmn,hijklmnoijklmnopjklmnopqklmnopqrlmnopqr,smno' +
                                    'pqrstnopqrst,u';
  FTestData[ 1].Enabled          := false;

  FTestData[ 2].Output           := 'cdbb41d1164ef06788b8b3f0fcb157de981311f0bc76752c952' +
                                    '075fcb14d1c133b27ddc7ad6b6b8c180346d0fe18694b';
  FTestData[ 2].OutputUTFStrTest := '2cbf89df082d30f912fc15415e3e0ee75cf2d5ebdd2b32626d6' +
                                    'a94ff86e40c68cce673c5a28b59a1ab5f879d11698bdb';
  FTestData[ 2].Input            := 'This test vector intended to detect last zeroized block ' +
                                    'necessity decision error. It has total length 111 bytes';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := '49b8d662fc136462591f9a96a64d28ea8fb03b7b943dd3400f2' +
                                    '633effcab37502927736f19bdeecce842801f41ab3e26';
  FTestData[ 3].OutputUTFStrTest := '32a077958cdd604f0224941d17c52b37d441152ab0b19bf7594' +
                                    '50f39a3c94f1d8521c20e5add06cbb5f56082265f43c5';
  FTestData[ 3].Input            := 'This test vector intended to detect last zeroized block ' +
                                    'necessity decision error. It has total length 112 bytes.';
  FTestData[ 3].Enabled          := true;
end;

procedure TestTHash_SHA384.TearDown;
begin
  FHash_SHA384.Free;
  FHash_SHA384 := nil;
end;

procedure TestTHash_SHA384.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_SHA384);
end;

procedure TestTHash_SHA384.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_SHA384);
end;

procedure TestTHash_SHA384.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_SHA384);
end;

procedure TestTHash_SHA384.TestDigestSize;
begin
  CheckEquals(48, FHash_SHA384.DigestSize);
end;

procedure TestTHash_SHA384.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_SHA384.IsPasswordHash);
end;

procedure TestTHash_SHA384.TestBlockSize;
begin
  CheckEquals(128, FHash_SHA384.BlockSize);
end;

procedure TestTHash_SHA384.TestCalcStream;
begin
  DoTestCalcStream(FHash_SHA384);
end;

procedure TestTHash_SHA384.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_SHA384);
end;

procedure TestTHash_SHA512.SetUp;
begin
  FHash_SHA512 := THash_SHA512.Create;
  SetLength(FTestData, 4);

  FTestData[ 0].Output           := 'ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9' +
                                    'eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d44' +
                                    '23643ce80e2a9ac94fa54ca49f';
//  FTestData[ 0].OutputUTFStrTest := '';
  FTestData[ 0].Input            := 'ab,c';
  FTestData[ 0].Enabled          := false;

  FTestData[ 1].Output           := '8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa1729' +
                                    '9aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329' +
                                    'eeb6dd26545e96e55b874be909';
//  FTestData[ 1].OutputUTFStrTest := '';
  FTestData[ 1].Input            := 'abcdefghbcdefghicdefghijdefghij,kefghijklfghijklmgh' +
                                    'ijklmn,hijklmnoijklmnopjklmnopqklmnopqrlmnopqr,smno' +
                                    'pqrstnopqrst,u';
  FTestData[ 1].Enabled          := false;

  FTestData[ 2].Output           := 'b4dd09998c54420c9445fb0706715f595435880da13fc56d2f5' +
                                    '5b47a86cd9e59a5ee9564f3bc8e91ed9ab6b2a5db2561a3bd56' +
                                    'e21defda4faf831da96210104d';
  FTestData[ 2].OutputUTFStrTest := 'a3c375fd0d3c264e4197cb4a7087e854d487c1d6e1011408b3d' +
                                    'a60e48d51596c950566215cf8bc917354862c7de4e38f155aed' +
                                    '1ee9f3f3416c5364782a534ac2';
  FTestData[ 2].Input            := 'This test vector intended to detect last zeroized block ' +
                                    'necessity decision error. It has total length 111 bytes';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'ad80509dcad277f40647311294f9b007165ae8456829d4befdf' +
                                    'd0de536c05c8ceec7dbe6d9dac88578fa3037d37b81382c0ae1' +
                                    '4c2fd9388fde50105ad1d7d993';
  FTestData[ 3].OutputUTFStrTest := 'f5fd5871f5d7c55b230fae0d48d054dd6732aa35a0b72074721' +
                                    'b3a28fb685ed5560dad9864a35c16f237696666503bada6cc77' +
                                    '082258f65f265c501b31dcf92b';
  FTestData[ 3].Input            := 'This test vector intended to detect last zeroized block ' +
                                    'necessity decision error. It has total length 112 bytes.';
  FTestData[ 3].Enabled          := true;
end;

procedure TestTHash_SHA512.TearDown;
begin
  FHash_SHA512.Free;
  FHash_SHA512 := nil;
end;

procedure TestTHash_SHA512.TestDigestSize;
begin
  CheckEquals(64, FHash_SHA512.DigestSize);
end;

procedure TestTHash_SHA512.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_SHA512.IsPasswordHash);
end;

procedure TestTHash_SHA512.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_SHA512);
end;

procedure TestTHash_SHA512.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_SHA512);
end;

procedure TestTHash_SHA512.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_SHA512);
end;

procedure TestTHash_SHA512.TestCalcStream;
begin
  DoTestCalcStream(FHash_SHA512);
end;

procedure TestTHash_SHA512.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_SHA512);
end;

procedure TestTHash_Haval128.SetUp;
begin
  FHash_Haval128 := THash_Haval128.Create;
  SetLength(FTestData, 18);

  FTestData[ 0].Output           := 'c68f39913f901f3ddf44c707357a7d70';
  FTestData[ 0].OutputUTFStrTest := 'c68f39913f901f3ddf44c707357a7d70';
  FTestData[ 0].Input            := '';
  FTestData[ 0].PaddingByte      := 1;
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '0cd40739683e15f01ca5dbceef4059f1';
  FTestData[ 1].OutputUTFStrTest := 'f2ac5ac2aae01fc184ef399da42d5865';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].PaddingByte      := 1;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'dc1f3c893d17cc4edd9ae94af76a0af0';
  FTestData[ 2].OutputUTFStrTest := 'b0b47bdc3c2434256b49c77675bd0aab';
  FTestData[ 2].Input            := 'HAVAL';
  FTestData[ 2].PaddingByte      := 1;
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'd4be2164ef387d9f4d46ea8efb180cf5';
  FTestData[ 3].OutputUTFStrTest := 'a74975d492868f80184a785e163d6a1a';
  FTestData[ 3].Input            := '0123456789';
  FTestData[ 3].PaddingByte      := 1;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'dc502247fb3eb8376109eda32d361d82';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].PaddingByte      := 1;
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'de5eb3f7d9eb08fae7a07d68e3047ec6';
  FTestData[ 5].OutputUTFStrTest := 'f68c39679f1660c0504feaa4d5958587';
  FTestData[ 5].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[ 5].PaddingByte      := 1;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := '4806b64dae93d3606308310a439e2a3a';
  FTestData[ 6].OutputUTFStrTest := 'dc48ac538e085f81571d4a64aca44fe4';
  FTestData[ 6].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[ 6].PaddingByte      := 1;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '8beaa7dd5bb591c8009e429d79041813';
//  FTestData[ 7].OutputUTFStrTest := '';
  FTestData[ 7].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 7].PaddingByte      := 1;
  FTestData[ 7].Enabled          := false;

  FTestData[ 8].Output           := '8beaa7dd5bb591c8009e429d79041813';
  FTestData[ 8].OutputUTFStrTest := '7669b7e0b3a872b8f4f48c5351c4c9c5';
  SetLength(FTestData[ 8].Input, 1000000);
  FillChar(FTestData[ 8].Input[low(FTestData[ 8].Input)], 1000000, 'a');
  FTestData[ 8].PaddingByte      := 1;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '1bdc556b29ad02ec09af8c66477f2a87';
  FTestData[ 9].OutputUTFStrTest := '1bdc556b29ad02ec09af8c66477f2a87';
  FTestData[ 9].Input            := '';
  FTestData[ 9].PaddingByte      := 128;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '24d2bc955a219e3e06462c91b555cfa1';
  FTestData[10].OutputUTFStrTest := 'fa53172579efb3ba63cf4b32e4f66bdd';
  FTestData[10].Input            := 'a';
  FTestData[10].PaddingByte      := 128;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '16c743e5eefd3266ed50deac6c30313e';
  FTestData[11].OutputUTFStrTest := 'c0716b442299437c01885a4e6335b2c2';
  FTestData[11].Input            := 'HAVAL';
  FTestData[11].PaddingByte      := 128;
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := '82d163440f6e853229a97007ec4af0e5';
  FTestData[12].OutputUTFStrTest := '9eb5e08841eb1cdab920d91660339340';
  FTestData[12].Input            := '0123456789';
  FTestData[12].PaddingByte      := 128;
  FTestData[12].Enabled          := true;

  FTestData[13].Output           := '92e8ec9ad7fd209d97e9ce21b50440e9';
//  FTestData[13].OutputUTFStrTest := '';
  FTestData[13].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[13].PaddingByte      := 128;
  FTestData[13].Enabled          := false;

  FTestData[14].Output           := '4ae2f37cef9275cce0d73f6a1eb9cdd8';
  FTestData[14].OutputUTFStrTest := '821ea5eb3f12c7cb429eb4f44c60112c';
  FTestData[14].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[14].PaddingByte      := 128;
  FTestData[14].Enabled          := true;

  FTestData[15].Output           := '3e1846cda3c9542944672b7150d0f38c';
  FTestData[15].OutputUTFStrTest := '67c7f95b227d60218508df6c7b4b9fe2';
  FTestData[15].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[15].PaddingByte      := 128;
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := '41b74ec225c9fb7a8e24840a98141b39';
  //FTestData[16].OutputUTFStrTest := '';
  FTestData[16].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[16].PaddingByte      := 128;
  FTestData[16].Enabled          := false;

  FTestData[17].Output           := '41b74ec225c9fb7a8e24840a98141b39';
  FTestData[17].OutputUTFStrTest := '85b87eb2cfdf9dc3e6bf25b654c28f5c';
  SetLength(FTestData[17].Input, 1000000);
  FillChar(FTestData[17].Input[low(FTestData[17].Input)], 1000000, 'a');
  FTestData[17].PaddingByte      := 128;
  FTestData[17].Enabled          := true;
end;

procedure TestTHash_Haval128.TearDown;
begin
  FHash_Haval128.Free;
  FHash_Haval128 := nil;
end;

procedure TestTHash_Haval128.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_HAVAL128);
end;

procedure TestTHash_Haval128.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_HAVAL128);
end;

procedure TestTHash_Haval128.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Haval128);
end;

procedure TestTHash_Haval128.TestDigestSize;
begin
  CheckEquals(16, FHash_Haval128.DigestSize);
end;

procedure TestTHash_Haval128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Haval128.IsPasswordHash);
end;

procedure TestTHash_Haval128.TestCalcStream;
begin
  DoTestCalcStream(FHash_Haval128);
end;

procedure TestTHash_Haval128.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Haval128);
end;

procedure TestTHash_Haval160.SetUp;
begin
  FHash_Haval160 := THash_Haval160.Create;
  SetLength(FTestData, 18);

  FTestData[ 0].Output           := 'd353c3ae22a25401d257643836d7231a9a95f953';
  FTestData[ 0].OutputUTFStrTest := 'd353c3ae22a25401d257643836d7231a9a95f953';
  FTestData[ 0].Input            := '';
  FTestData[ 0].PaddingByte      := 1;
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '4da08f514a7275dbc4cece4a347385983983a830';
  FTestData[ 1].OutputUTFStrTest := 'd976681ea27160c08ebab0032a76653fae848376';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].PaddingByte      := 1;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '8822bc6f3e694e73798920c77ce3245120dd8214';
  FTestData[ 2].OutputUTFStrTest := 'cb5a03288450a452caec0e9154cb56ccaa007361';
  FTestData[ 2].Input            := 'HAVAL';
  FTestData[ 2].PaddingByte      := 1;
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'be68981eb3ebd3f6748b081ee5d4e1818f9ba86c';
  FTestData[ 3].OutputUTFStrTest := '5433add25965d4cef4158530ea11d9cabf5dfae0';
  FTestData[ 3].Input            := '0123456789';
  FTestData[ 3].PaddingByte      := 1;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'eba9fa6050f24c07c29d1834a60900ea4e32e61b';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].PaddingByte      := 1;
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '97dc988d97caae757be7523c4e8d4ea63007a4b9';
  FTestData[ 5].OutputUTFStrTest := 'e7052bbd65c7608cf0589f6471d85d7c0f02a6fd';
  FTestData[ 5].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[ 5].PaddingByte      := 1;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'ba27e0d51b9ba140804252413c52b42dfe97214b';
  FTestData[ 6].OutputUTFStrTest := '1eecea4c278e9a797bbcfce396dcebca7243623b';
  FTestData[ 6].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[ 6].PaddingByte      := 1;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '5ea7fa9a0236aad66a1da8f161985c6e3dae2b81';
//  FTestData[ 7].OutputUTFStrTest := '';
  FTestData[ 7].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 7].PaddingByte      := 1;
  FTestData[ 7].Enabled          := false;

  FTestData[ 8].Output           := '5ea7fa9a0236aad66a1da8f161985c6e3dae2b81';
  FTestData[ 8].OutputUTFStrTest := 'b0de8db36f55ea32b57d4333114d4a9d47ce53cd';
  SetLength(FTestData[ 8].Input, 1000000);
  FillChar(FTestData[ 8].Input[low(FTestData[ 8].Input)], 1000000, 'a');
  FTestData[ 8].PaddingByte      := 1;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := 'fe79d0a044ffb75d5354668d664e4f4b9cc33477';
  FTestData[ 9].OutputUTFStrTest := 'fe79d0a044ffb75d5354668d664e4f4b9cc33477';
  FTestData[ 9].Input            := '';
  FTestData[ 9].PaddingByte      := 128;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '5e1610fced1d3adb0bb18e92ac2b11f0bd99d8ed';
  FTestData[10].OutputUTFStrTest := '871624bcbb8c01039b10dbd18f4e85ef2847beec';
  FTestData[10].Input            := 'a';
  FTestData[10].PaddingByte      := 128;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '8e568ad6ccd58d17e0a11e92183232e0d1d2e9bf';
  FTestData[11].OutputUTFStrTest := '53374669cfde8f3a5013ff3ba218ce84d4fe0764';
  FTestData[11].Input            := 'HAVAL';
  FTestData[11].PaddingByte      := 128;
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := '700d43a9b5e38300303fd4e25a6a326beb4a2241';
  FTestData[12].OutputUTFStrTest := '92acab606db474de51c93cb812b125f0a71c413b';
  FTestData[12].Input            := '0123456789';
  FTestData[12].PaddingByte      := 128;
  FTestData[12].Enabled          := true;

  FTestData[13].Output           := '1dd40aeab9610585fcae7492ff3b893c2a018f4e';
//  FTestData[13].OutputUTFStrTest := '';
  FTestData[13].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[13].PaddingByte      := 1;
  FTestData[13].Enabled          := false;

  FTestData[14].Output           := '485abb76ed2f5ac8bb86ddeb8cb4c54cf5bb077b';
  FTestData[14].OutputUTFStrTest := '82424bfabb7afd551fb01478e0bc26099300cd1b';
  FTestData[14].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[14].PaddingByte      := 128;
  FTestData[14].Enabled          := true;

  FTestData[15].Output           := '7e3ec827726ae5ce4f4f67614395aa1c0602551a';
  FTestData[15].OutputUTFStrTest := '297a10aab083211007ffa25be84fcfdb9cb8a94d';
  FTestData[15].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[15].PaddingByte      := 128;
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := '687e9073f7ec5f01ea4744b86ef40e13aaacf0a4';
//  FTestData[16].OutputUTFStrTest := '';
  FTestData[16].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[16].PaddingByte      := 128;
  FTestData[16].Enabled          := false;

  FTestData[17].Output           := '687e9073f7ec5f01ea4744b86ef40e13aaacf0a4';
  FTestData[17].OutputUTFStrTest := 'd65ef2dcb081c97494e84407033cb29415a80730';
  SetLength(FTestData[17].Input, 1000000);
  FillChar(FTestData[17].Input[low(FTestData[17].Input)], 1000000, 'a');
  FTestData[17].PaddingByte      := 128;
  FTestData[17].Enabled          := true;
end;

procedure TestTHash_Haval160.TearDown;
begin
  FHash_Haval160.Free;
  FHash_Haval160 := nil;
end;

procedure TestTHash_Haval160.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_HAVAL160);
end;

procedure TestTHash_Haval160.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_HAVAL160);
end;

procedure TestTHash_Haval160.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Haval160);
end;

procedure TestTHash_Haval160.TestDigestSize;
begin
  CheckEquals(20, FHash_Haval160.DigestSize);
end;

procedure TestTHash_Haval160.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Haval160.IsPasswordHash);
end;

procedure TestTHash_Haval160.TestCalcStream;
begin
  DoTestCalcStream(FHash_Haval160);
end;

procedure TestTHash_Haval160.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Haval160);
end;

procedure TestTHash_Haval192.SetUp;
begin
  FHash_Haval192 := THash_Haval192.Create;
  SetLength(FTestData, 18);

  FTestData[ 0].Output           := '4a8372945afa55c7dead800311272523ca19d42ea47b72da';
  FTestData[ 0].OutputUTFStrTest := '4a8372945afa55c7dead800311272523ca19d42ea47b72da';
  FTestData[ 0].Input            := '';
  FTestData[ 0].PaddingByte      := 1;
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '856c19f86214ea9a8a2f0c4b758b973cce72a2d8ff55505c';
  FTestData[ 1].OutputUTFStrTest := 'ea49939cb5a812d962cb3593dd37e35cdcd208961be61bf5';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].PaddingByte      := 1;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '0c1396d7772689c46773f3daaca4efa982adbfb2f1467eea';
  FTestData[ 2].OutputUTFStrTest := '5eb34e664e18f78da615ab3424243c49b054af95722509e8';
  FTestData[ 2].Input            := 'HAVAL';
  FTestData[ 2].PaddingByte      := 1;
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'c3a5420bb9d7d82a168f6624e954aaa9cdc69fb0f67d785e';
  FTestData[ 3].OutputUTFStrTest := 'ca16d8d258a68bb8443fe6185558e44f34ddad8ba86199e0';
  FTestData[ 3].Input            := '0123456789';
  FTestData[ 3].PaddingByte      := 1;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '2e2e581d725e799fda1948c75e85a28cfe1cf0c6324a1ada';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].PaddingByte      := 1;
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'e5c9f81ae0b31fc8780fc37cb63bb4ec96496f79a9b58344';
  FTestData[ 5].OutputUTFStrTest := 'd1458c150e3330016f0ebdb1f7003e0eba960739a6830923';
  FTestData[ 5].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[ 5].PaddingByte      := 1;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := '8c80602a16fcca8332c08446ea61a2fbc74e05d3361f0e4d';
  FTestData[ 6].OutputUTFStrTest := '517f983928861f8a86402101e500fb613070177cfc93914c';
  FTestData[ 6].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[ 6].PaddingByte      := 1;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := 'aa15056802a32823332dd551ebe3e39918d6bc9e1fa293b1';
//  FTestData[ 7].OutputUTFStrTest := '';
  FTestData[ 7].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 7].PaddingByte      := 1;
  FTestData[ 7].Enabled          := false;

  FTestData[ 8].Output           := 'aa15056802a32823332dd551ebe3e39918d6bc9e1fa293b1';
  FTestData[ 8].OutputUTFStrTest := '80c428dfb6bc4179803c47f840a98ffeb527b491b06cdfd6';
  SetLength(FTestData[ 8].Input, 1000000);
  FillChar(FTestData[ 8].Input[low(FTestData[ 8].Input)], 1000000, 'a');
  FTestData[ 8].PaddingByte      := 1;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '51fa9e28c96865207ed6dae2eaa1d8af6e7de2783ebec4b4';
  FTestData[ 9].OutputUTFStrTest := '51fa9e28c96865207ed6dae2eaa1d8af6e7de2783ebec4b4';
  FTestData[ 9].Input            := '';
  FTestData[ 9].PaddingByte      := 128;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := 'a1446e6cedb4b28bc6e13d4d1d2694e9ce4a3d942c73589e';
  FTestData[10].OutputUTFStrTest := '157776b815376afdba30a5de81cb2c3eaa6d28ed7b19bbad';
  FTestData[10].Input            := 'a';
  FTestData[10].PaddingByte      := 128;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '74aa31182ff09bcce453a7f71b5a7c5e80872fa90cd93ae4';
  FTestData[11].OutputUTFStrTest := '056003283fb434178a1ff76764812885196cdc74604c967b';
  FTestData[11].Input            := 'HAVAL';
  FTestData[11].PaddingByte      := 128;
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := 'ca05546ffa4b69dafa7c04424cc10802a2523efcb8bebb61';
  FTestData[12].OutputUTFStrTest := '2d95bdbb37c3c74118c739030345f0acd66551b3cd6486d7';
  FTestData[12].Input            := '0123456789';
  FTestData[12].PaddingByte      := 128;
  FTestData[12].Enabled          := true;

  FTestData[13].Output           := '5a238735d9e902e16cad81229cc981a763508c73f4a52dd0';
//  FTestData[13].OutputUTFStrTest := '';
  FTestData[13].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[13].PaddingByte      := 1;
  FTestData[13].Enabled          := false;

  FTestData[14].Output           := 'd51d73eb03b0d841c24f2007aa9159f0f70a971cbfbed33c';
  FTestData[14].OutputUTFStrTest := 'cfcd7add4233885ec083a5a25662b29afbcbbcb4e6f081c7';
  FTestData[14].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[14].PaddingByte      := 128;
  FTestData[14].Enabled          := true;

  FTestData[15].Output           := '1cee084b711ef399076a4cfa095a81dc6e1667f3c8207204';
  FTestData[15].OutputUTFStrTest := '6e2c2b45cc4efd0422ae3a6c0cf4dc9a400a901723881733';
  FTestData[15].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[15].PaddingByte      := 128;
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := 'f5608294798348bfa3fc45f72954a0e980b15804b4c56674';
//  FTestData[16].OutputUTFStrTest := '';
  FTestData[16].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[16].PaddingByte      := 128;
  FTestData[16].Enabled          := false;

  FTestData[17].Output           := 'f5608294798348bfa3fc45f72954a0e980b15804b4c56674';
  FTestData[17].OutputUTFStrTest := 'ff7c15641ca292000ba31bb863b7f3b524943e2ed64c4b12';
  SetLength(FTestData[17].Input, 1000000);
  FillChar(FTestData[17].Input[low(FTestData[17].Input)], 1000000, 'a');
  FTestData[17].PaddingByte      := 128;
  FTestData[17].Enabled          := true;
end;

procedure TestTHash_Haval192.TearDown;
begin
  FHash_Haval192.Free;
  FHash_Haval192 := nil;
end;

procedure TestTHash_Haval192.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_HAVAL192);
end;

procedure TestTHash_Haval192.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_HAVAL192);
end;

procedure TestTHash_Haval192.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Haval192);
end;

procedure TestTHash_Haval192.TestDigestSize;
begin
  CheckEquals(24, FHash_Haval192.DigestSize);
end;

procedure TestTHash_Haval192.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Haval192.IsPasswordHash);
end;

procedure TestTHash_Haval192.TestCalcStream;
begin
  DoTestCalcStream(FHash_Haval192);
end;

procedure TestTHash_Haval192.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Haval192);
end;

procedure TestTHash_Haval224.SetUp;
begin
  FHash_Haval224 := THash_Haval224.Create;
  SetLength(FTestData, 18);

  FTestData[ 0].Output           := '3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e';
  FTestData[ 0].OutputUTFStrTest := '3e56243275b3b81561750550e36fcd676ad2f5dd9e15f2e89e6ed78e';
  FTestData[ 0].Input            := '';
  FTestData[ 0].PaddingByte      := 1;
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '742f1dbeeaf17f74960558b44f08aa98bdc7d967e6c0ab8f799b3ac1';
  FTestData[ 1].OutputUTFStrTest := '949b0e1c272fad467366c614cb79c878f648363c6e34e4a6af2bf0c9';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].PaddingByte      := 1;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '85538ffc06f3b1c693c792c49175639666f1dde227da8bd000c1e6b4';
  FTestData[ 2].OutputUTFStrTest := 'c731136eca1d43c14c0fa34544776e06f1a911ebd245a7ae4cd6624d';
  FTestData[ 2].Input            := 'HAVAL';
  FTestData[ 2].PaddingByte      := 1;
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'bebd7816f09baeecf8903b1b9bc672d9fa428e462ba699f814841529';
  FTestData[ 3].OutputUTFStrTest := '97c760aec423f4f0d4fab68e0ea57ca00a402ca258c41495bf396337';
  FTestData[ 3].Input            := '0123456789';
  FTestData[ 3].PaddingByte      := 1;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'a0ac696cdb2030fa67f6cc1d14613b1962a7b69b4378a9a1b9738796';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].PaddingByte      := 1;
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '3e63c95727e0cd85d42034191314401e42ab9063a94772647e3e8e0f';
  FTestData[ 5].OutputUTFStrTest := '09293b232655058426832f0ceb13ff041688f4fa43243b66a2c19677';
  FTestData[ 5].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[ 5].PaddingByte      := 1;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'adf788362468585753a4ebb59c44c8934d2995c6305beb9345ddf485';
  FTestData[ 6].OutputUTFStrTest := '0f4b666b0257088fe15e05a8b738c9bb7955b62369df9994b92049fe';
  FTestData[ 6].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[ 6].PaddingByte      := 1;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '0d53e2e5e768707ab94070f6f9b8accd9ad831076780443a2e659fdc';
//  FTestData[ 7].OutputUTFStrTest := '';
  FTestData[ 7].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 7].PaddingByte      := 1;
  FTestData[ 7].Enabled          := false;

  FTestData[ 8].Output           := '0d53e2e5e768707ab94070f6f9b8accd9ad831076780443a2e659fdc';
  FTestData[ 8].OutputUTFStrTest := 'e0d9ddda7cbdcde1ae543990fc5462193140b97c82646ce9379d751c';
  SetLength(FTestData[ 8].Input, 1000000);
  FillChar(FTestData[ 8].Input[low(FTestData[ 8].Input)], 1000000, 'a');
  FTestData[ 8].PaddingByte      := 1;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := 'aacd8950b239b05e8a40a0419afd3bbed206623913d8a6dfe71d174b';
  FTestData[ 9].OutputUTFStrTest := 'aacd8950b239b05e8a40a0419afd3bbed206623913d8a6dfe71d174b';
  FTestData[ 9].Input            := '';
  FTestData[ 9].PaddingByte      := 128;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '54a26096c951725228d34a1b55c2db5c28446e6b243fe2ae78623a4b';
  FTestData[10].OutputUTFStrTest := 'a4575897b531c3e05a50f950639c47b65ec5e4047af26410773aeb52';
  FTestData[10].Input            := 'a';
  FTestData[10].PaddingByte      := 128;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := 'f9040eebae11709245501beffb5fb849f88a9086f24df3a55a03a01a';
  FTestData[11].OutputUTFStrTest := '4eaeb545094367efa73ad92f0c4eff66d3ed8ad57c125bbfe4f98c74';
  FTestData[11].Input            := 'HAVAL';
  FTestData[11].PaddingByte      := 128;
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := '144cb2de11f05df7c356282a3b485796da653f6b702868c7dcf4ae76';
  FTestData[12].OutputUTFStrTest := 'c2762d3cfced507c48dd8e0827cffb020c26239cd8fcebcd65ddadb7';
  FTestData[12].Input            := '0123456789';
  FTestData[12].PaddingByte      := 128;
  FTestData[12].Enabled          := true;

  FTestData[13].Output           := 'fbb63f06592fb9aa4f59652b99bc53c1ff72675726c71326c682dabc';
//  FTestData[13].OutputUTFStrTest := '';
  FTestData[13].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[13].PaddingByte      := 1;
  FTestData[13].Enabled          := false;

  FTestData[14].Output           := '1120b26105044df0b4e5b904705f3b8cbbc14a52b73301c300baff8a';
  FTestData[14].OutputUTFStrTest := 'e427422e29d14a7371874ebc3e3b04ab96766954074c8e7345b6fa10';
  FTestData[14].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[14].PaddingByte      := 128;
  FTestData[14].Enabled          := true;

  FTestData[15].Output           := '752a1ee3fc2185888a421e148d6a3b8fb33ac20ba0668598c11d755a';
  FTestData[15].OutputUTFStrTest := '4ead6b5944f5453f9f8abf9c863687ac0e7d6b5906d8334f5f334b38';
  FTestData[15].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[15].PaddingByte      := 128;
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := 'aff21cea7b3294dd02e6de843650fe82eb51cdd1e9d8873b13834717';
//  FTestData[16].OutputUTFStrTest := '';
  FTestData[16].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[16].PaddingByte      := 128;
  FTestData[16].Enabled          := false;

  FTestData[17].Output           := 'aff21cea7b3294dd02e6de843650fe82eb51cdd1e9d8873b13834717';
  FTestData[17].OutputUTFStrTest := 'ece302f7e317c2bbab56f1e29ac123441a241297f5696465f8b7ed6d';
  SetLength(FTestData[17].Input, 1000000);
  FillChar(FTestData[17].Input[low(FTestData[17].Input)], 1000000, 'a');
  FTestData[17].PaddingByte      := 128;
  FTestData[17].Enabled          := true;
end;

procedure TestTHash_Haval224.TearDown;
begin
  FHash_Haval224.Free;
  FHash_Haval224 := nil;
end;

procedure TestTHash_Haval224.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_HAVAL224);
end;

procedure TestTHash_Haval224.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_HAVAL224);
end;

procedure TestTHash_Haval224.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Haval224);
end;

procedure TestTHash_Haval224.TestDigestSize;
begin
  CheckEquals(28, FHash_Haval224.DigestSize);
end;

procedure TestTHash_Haval224.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Haval224.IsPasswordHash);
end;

procedure TestTHash_Haval224.TestCalcStream;
begin
  DoTestCalcStream(FHash_Haval224);
end;

procedure TestTHash_Haval224.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Haval224);
end;

procedure TestTHash_Haval256.SetUp;
begin
  FHash_Haval256 := THash_Haval256.Create;
  SetLength(FTestData, 20);

  FTestData[ 0].Output           := 'be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330';
  FTestData[ 0].OutputUTFStrTest := 'be417bb4dd5cfb76c7126f4f8eeb1553a449039307b1a3cd451dbfdc0fbbe330';
  FTestData[ 0].Input            := '';
  FTestData[ 0].PaddingByte      := 1;
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'de8fd5ee72a5e4265af0a756f4e1a1f65c9b2b2f47cf17ecf0d1b88679a3e22f';
  FTestData[ 1].OutputUTFStrTest := '42f59f1483a46c33f1d8c19a2b3bfafc5ad8855b6be91f02b1238476764c709f';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].PaddingByte      := 1;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '153d2c81cd3c24249ab7cd476934287af845af37f53f51f5c7e2be99ba28443f';
  FTestData[ 2].OutputUTFStrTest := '3c94e3e4c74a5c873d8f9a12636ec216ff0b8033e03ec6e584ff4c3d294a86db';
  FTestData[ 2].Input            := 'HAVAL';
  FTestData[ 2].PaddingByte      := 1;
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := '357e2032774abbf5f04d5f1dec665112ea03b23e6e00425d0df75ea155813126';
  FTestData[ 3].OutputUTFStrTest := 'f4abfc9b62f537b3d525b91f05653ef6ee439896921256aaf5f6e808172fad38';
  FTestData[ 3].Input            := '0123456789';
  FTestData[ 3].PaddingByte      := 1;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'c9c7d8afa159fd9e965cb83ff5ee6f58aeda352c0eff005548153a61551c38ee';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'ab,cdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].PaddingByte      := 1;
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'b45cb6e62f2b1320e4f8f1b0b273d45add47c321fd23999dcf403ac37636d963';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg,hijklmnopqrstuvwxyz012345678,9';
  FTestData[ 5].PaddingByte      := 1;
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := '42bb773476b0e978e7fa7414b2e7ecf0dc0a2accb96ade5d815d0e4706969272';
  FTestData[ 6].OutputUTFStrTest := 'acff80b9410d5116f98979c2440c3fdb0337279cb19971f7946958628d2178fc';
  FTestData[ 6].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899876543210' +
                                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899876543210';
  FTestData[ 6].PaddingByte      := 1;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := 'e7467dad3b4f59c182a7869816ec15c8b59e4c5038ff5afbff60e6d44041a670';
  FTestData[ 7].OutputUTFStrTest := '982f54d460ebe0221fd30391c0b58d139ef98335ffb5ba4551a4cd4b7fb9596e';
  FTestData[ 7].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[ 7].PaddingByte      := 1;
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '3f2be6dd53dc7944290e8939192bcccc8077c99b622e0c20355942dd6a4ec009';
//  FTestData[ 8].OutputUTFStrTest := '';
  FTestData[ 8].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[ 8].PaddingByte      := 1;
  FTestData[ 8].Enabled          := false;

  FTestData[ 9].Output           := '3f2be6dd53dc7944290e8939192bcccc8077c99b622e0c20355942dd6a4ec009';
  FTestData[ 9].OutputUTFStrTest := '8a408f644a207606c853c4b297cf4b1b2768e91ab5b8ef6ce7c6a6c2cc1b056e';
  SetLength(FTestData[ 9].Input, 1000000);
  FillChar(FTestData[ 9].Input[low(FTestData[ 9].Input)], 1000000, 'a');
  FTestData[ 9].PaddingByte      := 1;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '5981d3f8cce7f5674752595f4ad24c184ba1c738c986d4d2eddf2bd86c3f8679';
  FTestData[10].OutputUTFStrTest := '5981d3f8cce7f5674752595f4ad24c184ba1c738c986d4d2eddf2bd86c3f8679';
  FTestData[10].Input            := '';
  FTestData[10].PaddingByte      := 128;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '166f2218e0994a78ebad3feab0211b612b14e93e5cceb60e6f143df0fa166d39';
  FTestData[11].OutputUTFStrTest := '8e7ae4af7207e8599142d23d097de42d9f7b5bd314de95261eff46d305834157';
  FTestData[11].Input            := 'a';
  FTestData[11].PaddingByte      := 128;
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := '217bfdf84f5c775596c2f13ceea7417cd4e198d53ca24902f9717585ec5789ac';
  FTestData[12].OutputUTFStrTest := '45e7e26a86f323b0fe52aecb5a354f683b0685aaf0a99d326baa56117bf60368';
  FTestData[12].Input            := 'HAVAL';
  FTestData[12].PaddingByte      := 128;
  FTestData[12].Enabled          := true;

  FTestData[13].Output           := 'a6828eeb82d5a9cbfc7c522ad4b3c38a42753deceb20fb3a6fabc0da8ccd6a1a';
  FTestData[13].OutputUTFStrTest := '835505ef404be97dde1bcaf354cab1e88282bb2c03bb973ea80dc323033b64d3';
  FTestData[13].Input            := '0123456789';
  FTestData[13].PaddingByte      := 128;
  FTestData[13].Enabled          := true;

  FTestData[14].Output           := '1a1dc8099bdaa7f35b4da4e805f1a28fee909d8dee920198185cbcaed8a10a8d';
//  FTestData[14].OutputUTFStrTest := '';
  FTestData[14].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[14].PaddingByte      := 1;
  FTestData[14].Enabled          := false;

  FTestData[15].Output           := 'c5647fc6c1877fff96742f27e9266b6874894f41a08f5913033d9d532aeddb39';
  FTestData[15].OutputUTFStrTest := '60811e064a010c9324c386084e7e386dc7371276571d6ba4ff38495ea68cd90c';
  FTestData[15].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[15].PaddingByte      := 128;
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := '88c8334686f5ae277de90a2267c7e52ec6e2fe708eedb067d136e046613f2253';
  FTestData[16].OutputUTFStrTest := 'd4e9a56083f2bf6ec457b646698df7357017c53b58f0732d517796d69d057f53';
  FTestData[16].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899876543210' +
                                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz01234567899876543210';
  FTestData[16].PaddingByte      := 128;
  FTestData[16].Enabled          := true;

  FTestData[17].Output           := '7da3e3411ae031fa241e6f2f7deaf62827e8e97a2865ce5c1b67da2b6065efe4';
  FTestData[17].OutputUTFStrTest := '1dd3aaf5bc03f3674732a28523f57ed24208d283e3836e5900ec8db0833b3f1c';
  FTestData[17].Input            := 'This test vector intended to detect last zeroized ' +
                                    'block necessity decision error. For this detection' +
                                    ' it is 117 bytes.';
  FTestData[17].PaddingByte      := 128;
  FTestData[17].Enabled          := true;

  FTestData[18].Output           := '6d0efcb27421a2c45c14dd66f5de5e289893360ca2089c26ef491c01bd94b21a';
//  FTestData[18].OutputUTFStrTest := '';
  FTestData[18].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[18].PaddingByte      := 128;
  FTestData[18].Enabled          := false;

  FTestData[19].Output           := '6d0efcb27421a2c45c14dd66f5de5e289893360ca2089c26ef491c01bd94b21a';
  FTestData[19].OutputUTFStrTest := 'e42666d73cee62653aecbce6b1bbf76134bf441f8fb04ac7be826bc2493cd537';
  SetLength(FTestData[19].Input, 1000000);
  FillChar(FTestData[19].Input[low(FTestData[19].Input)], 1000000, 'a');
  FTestData[19].PaddingByte      := 128;
  FTestData[19].Enabled          := true;
end;

procedure TestTHash_Haval256.TearDown;
begin
  FHash_Haval256.Free;
  FHash_Haval256 := nil;
end;

procedure TestTHash_Haval256.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_HAVAL256);
end;

procedure TestTHash_Haval256.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_HAVAL256);
end;

procedure TestTHash_Haval256.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Haval256);
end;

procedure TestTHash_Haval256.TestDigestSize;
begin
  CheckEquals(32, FHash_Haval256.DigestSize);
end;

procedure TestTHash_Haval256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Haval256.IsPasswordHash);
end;

procedure TestTHash_Haval256.TestCalcStream;
begin
  DoTestCalcStream(FHash_Haval256);
end;

procedure TestTHash_Haval256.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Haval256);
end;

procedure TestTHash_Tiger_3Rounds.SetUp;
begin
  FHash_Tiger        := THash_Tiger.Create;
  FHash_Tiger.Rounds := 3;

  SetLength(FTestData, 9);

  FTestData[ 0].Output           := '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3';
  FTestData[ 0].OutputUTFStrTest := '3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93';
//  FTestData[ 1].OutputUTFStrTest := '';
  FTestData[ 1].Input            := 'ab,c';
  FTestData[ 1].Enabled          := false;

  FTestData[ 2].Output           := 'dd00230799f5009fec6debc838bb6a27df2b9d6f110c7937';
  FTestData[ 2].OutputUTFStrTest := '54d1b0b346b9597343ff5a43d89a99c35f1066cff8fb9d52';
  FTestData[ 2].Input            := 'Tiger';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'f71c8583902afb879edfe610f82c0d4786a3a534504486b5';
//  FTestData[ 3].OutputUTFStrTest := '';
  FTestData[ 3].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg,h,ijklmnopqrstuvwxyz0123456789+-';
  FTestData[ 3].Enabled          := false;

  FTestData[ 4].Output           := '48ceeb6308b87d46e95d656112cdf18d97915f9765658957';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+012345678,9';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '8a866829040a410c729ad23f5ada711603b3cdd357e4c15e';
  FTestData[ 5].OutputUTFStrTest := 'ec87318e83e4e0a3a449430f2090ff8312d1977ef8fc0b19';
  FTestData[ 5].Input            := 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham';
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'ce55a6afd591f5ebac547ff84f89227f9331dab0b611c889';
  FTestData[ 6].OutputUTFStrTest := '2a9c054f26080de941ac3a7853b0c9ff80f99b03510c1860';
  FTestData[ 6].Input            := 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '631abdd103eb9a3d245b6dfd4d77b257fc7439501d1568dd';
  FTestData[ 7].OutputUTFStrTest := '7fe631245eafd0a6fb2473c83a58a244ae60ea475880106b';
  FTestData[ 7].Input            := 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'c54034e5b43eb8005848a7e0ae6aac76e4ff590ae715fd25';
  FTestData[ 8].OutputUTFStrTest := '9decaa95dac2e5d11617989563ad8c94d3236809e023ff59';
  FTestData[ 8].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-';
  FTestData[ 8].Enabled          := true;
end;

procedure TestTHash_Tiger_3Rounds.TearDown;
begin
  FHash_Tiger.Free;
  FHash_Tiger := nil;
end;

procedure TestTHash_Tiger_3Rounds.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Tiger);
end;

procedure TestTHash_Tiger_3Rounds.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Tiger);
end;

procedure TestTHash_Tiger_3Rounds.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Tiger);
end;

procedure TestTHash_Tiger_3Rounds.TestDigestSize;
begin
  CheckEquals(24, FHash_Tiger.DigestSize);
end;

procedure TestTHash_Tiger_3Rounds.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Tiger.IsPasswordHash);
end;

procedure TestTHash_Tiger_3Rounds.TestSet2Rounds;
begin
  FHash_Tiger.Rounds := 2;
  CheckEquals(3, FHash_Tiger.Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestSet33Rounds;
begin
  FHash_Tiger.Rounds := 33;
  CheckEquals(32, FHash_Tiger.Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestSetRounds;
begin
  FHash_Tiger.Rounds := 5;
  CheckEquals(5, FHash_Tiger.Rounds);
end;

procedure TestTHash_Tiger_3Rounds.TestCalcStream;
begin
  DoTestCalcStream(FHash_Tiger);
end;

procedure TestTHash_Tiger_3Rounds.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Tiger);
end;

procedure TestTHash_Tiger_4Rounds.SetUp;
begin
  FHash_Tiger        := THash_Tiger.Create;
  FHash_Tiger.Rounds := 4;

  SetLength(FTestData, 9);

  FTestData[ 0].Output           := '24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194';
  FTestData[ 0].OutputUTFStrTest := '24cc78a7f6ff3546e7984e59695ca13d804e0b686e255194';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '538883c8fc5f28250299018e66bdf4fdb5ef7b65f2e91753';
//  FTestData[ 1].OutputUTFStrTest := '';
  FTestData[ 1].Input            := 'ab,c';
  FTestData[ 1].Enabled          := false;

  FTestData[ 2].Output           := 'aee020507279c0d2defcb767251cc0f824bbe38569d58ee4';
  FTestData[ 2].OutputUTFStrTest := '986161d6e753840ad58b8185244fe8ed76fcb282d51ec308';
  FTestData[ 2].Input            := 'Tiger';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := '439c699b3ca4f2d0cedc940fabca8941932a729a91950710';
//  FTestData[ 3].OutputUTFStrTest := '';
  FTestData[ 3].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefg,h,ijklmnopqrstuvwxyz0123456789+-';
  FTestData[ 3].Enabled          := false;

  FTestData[ 4].Output           := 'c5fe245ba8e9e3a056efd9f6cfa79cead8571a3c87fe62f1';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZ=abcdefghijklmnopqrstuvwxyz+012345678,9';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := '81100cdf2076b0e0392004f703449f41a37b840437b643ff';
  FTestData[ 5].OutputUTFStrTest := 'f637088a5036d9c5eb1b8f0624e63063a20cf6b2b646ae56';
  FTestData[ 5].Input            := 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham';
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'a1e027aa525a38589ac97cfa325dc08417b3445ab3c27452';
  FTestData[ 6].OutputUTFStrTest := '15bdac6f9d89b892f55f111a7f74cbcad6f9ff16ded07717';
  FTestData[ 6].Input            := 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge.';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := 'f72ca9fa0db3332782d7b8ccac29575490b8100803212003';
  FTestData[ 7].OutputUTFStrTest := '7d8fa74429c8d0010df6015816638891d52e301ec1756b72';
  FTestData[ 7].Input            := 'Tiger - A Fast New Hash Function, by Ross Anderson and Eli Biham, proceedings of Fast Software Encryption 3, Cambridge, 1996.';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '653b3075f1a85c6c74f1a9090b3c46239f29f0f92358e4e3';
  FTestData[ 8].OutputUTFStrTest := '21073aaf37e4a7bb0ccdaed0705a188f0c19c01f5c8bf7ce';
  FTestData[ 8].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-';
  FTestData[ 8].Enabled          := true;
end;

procedure TestTHash_Tiger_4Rounds.TestSet2Rounds;
begin
  FHash_Tiger.Rounds := 2;
  CheckEquals(3, FHash_Tiger.Rounds);
end;

procedure TestTHash_Tiger_4Rounds.TestSet33Rounds;
begin
  FHash_Tiger.Rounds := 33;
  CheckEquals(32, FHash_Tiger.Rounds);
end;

procedure TestTHash_Tiger_4Rounds.TestSetRounds;
begin
  FHash_Tiger.Rounds := 5;
  CheckEquals(5, FHash_Tiger.Rounds);
end;

procedure TestTHash_Tiger_4Rounds.TearDown;
begin
  FHash_Tiger.Free;
  FHash_Tiger := nil;
end;

procedure TestTHash_Tiger_4Rounds.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Tiger);
end;

procedure TestTHash_Tiger_4Rounds.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Tiger);
end;

procedure TestTHash_Tiger_4Rounds.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Tiger);
end;

procedure TestTHash_Tiger_4Rounds.TestDigestSize;
begin
  CheckEquals(24, FHash_Tiger.DigestSize);
end;

procedure TestTHash_Tiger_4Rounds.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Tiger.IsPasswordHash);
end;

procedure TestTHash_Tiger_4Rounds.TestCalcStream;
begin
  DoTestCalcStream(FHash_Tiger);
end;

procedure TestTHash_Tiger_4Rounds.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Tiger);
end;

procedure TestTHash_Panama.SetUp;
begin
  FHash_Panama := THash_Panama.Create;
  SetLength(FTestData, 7);

  FTestData[ 0].Output           := 'aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b';
  FTestData[ 0].OutputUTFStrTest := 'aa0cc954d757d7ac7779ca3342334ca471abd47d5952ac91ed837ecd5b16922b';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'a2a70386b81fb918be17f00ff3e3b376a0462c4dc2eec7f2c63202c8874c037d';
//  FTestData[ 1].OutputUTFStrTest := '';
  FTestData[ 1].Input            := 'abc';
  FTestData[ 1].Enabled          := false;

  FTestData[ 2].Output           := '8f3c497bb2cc4ee1c09f025bd72effef2689e5ade788e5b633c31f7e18c53fec';
  FTestData[ 2].OutputUTFStrTest := 'fa49e779c987a87a602b65a86e3796976681c04715fdc4a2611e9282185b1c77';
  FTestData[ 2].Input            := '0123456789abcdeffedcba987654321';
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := 'e7742dcf637952e28af6a4f55ab98f70285093162062a73a0baad08f579e83b3';
  FTestData[ 3].OutputUTFStrTest := 'c04b88a5dbbaadb4a3147fc381c6ad7e807a22ffee28a848542232f9f6fbbe22';
  FTestData[ 3].Input            := '0123456789abcdeffedcba9876543210';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '5f5ca355b90ac622b0aa7e654ef5f27e9e75111415b48b8afe3add1c6b89cba1';
  FTestData[ 4].OutputUTFStrTest := '1520099b14290b203224cd52c1ba43b372127d6a4abe146a2ce19fee5b55be4c';
  FTestData[ 4].Input            := 'The quick brown fox jumps over the lazy dog';
  FTestData[ 4].Enabled          := true;

  FTestData[ 5].Output           := '63a7a70172f9f1896a8b636f50e7a3950a63fe7ecac9de0441d9f75b8377f664';
  FTestData[ 5].OutputUTFStrTest := 'df9ef3392dba9cfc3509310276c21047dbb5a9e9f46d850d0c4ffa452a1a761f';
  FTestData[ 5].Input            := '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210' +
                                   '0123456789abcdeffedcba9876543210';
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'f5f407b0987499b2af57b19fa63d92fc88a217b08a6928ab521c720a04be6825';
//  FTestData[ 6].OutputUTFStrTest := '';
  // 10x
  FTestData[ 6].Input            := '0123456789abcdeffedcba987654321010123456789abcdeffedcba987654321010123456789abcdeffedcba98765432101>,3<0123456789abcdeffedcba98765432101';
  FTestData[ 6].Enabled          := false;
end;

procedure TestTHash_Panama.TearDown;
begin
  FHash_Panama.Free;
  FHash_Panama := nil;
end;

procedure TestTHash_Panama.TestDigestSize;
begin
  CheckEquals(32, FHash_Panama.DigestSize);
end;

procedure TestTHash_Panama.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Panama.IsPasswordHash);
end;

procedure TestTHash_Panama.TestBlockSize;
begin
  CheckEquals(32, FHash_Panama.BlockSize);
end;

procedure TestTHash_Panama.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Panama);
end;

procedure TestTHash_Panama.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Panama);
end;

procedure TestTHash_Panama.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Panama);
end;

procedure TestTHash_Panama.TestCalcStream;
begin
  DoTestCalcStream(FHash_Panama);
end;

procedure TestTHash_Panama.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Panama);
end;

procedure TestTHash_Whirlpool.SetUp;
begin
  FHash_Whirlpool := THash_Whirlpool.Create;
  SetLength(FTestData, 12);

  FTestData[ 0].Output           := 'b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca' +
                                    '0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1' +
                                    'a2b9004725d987d3635165d3c8';
  FTestData[ 0].OutputUTFStrTest := 'b3e1ab6eaf640a34f784593f2074416accd3b8e62c620175fca' +
                                    '0997b1ba2347339aa0d79e754c308209ea36811dfa40c1c32f1' +
                                    'a2b9004725d987d3635165d3c8';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'ee898fa681e89e1bba6764a5c07ced2f4a7bd1b8ec0637dd9ca' +
                                    'ca94d398db29baf6993b278231e2b7a3eecffe027928a4a4c9a' +
                                    'c6eb0de5f0fa58ede5949983d8';
  FTestData[ 1].OutputUTFStrTest := 'b31116c93f872f625cb09b270e0dc8e7ebc981a4fa671790c0d' +
                                    '5399aa0ada93ca24fc3fa8c510e81cd9070e0c8313afe5826b3' +
                                    '1887adeb7689988f9e95ad1ebf';
  FTestData[ 1].Input            := #$00;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '8786611bb3601e913e9f9e0a77181fa6279b286f162e48d32c7' +
                                    '79ad2ca0168eae66bf50bb69fb889eaeabafd5613ff8d0aecba' +
                                    '52d8a1bcdd48935fa416a10cb8';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := '<\x80>,63!<\x00>';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := 'f4b620445ae62431dbd6dbcec64d2a3031cd2f48df5e755f30b' +
                                    '3d069929ed4b4eda0ae65441bc86746021fb7f2167f84d67566' +
                                    'efaba003f0abb67a42a2ce5b13';
  FTestData[ 3].OutputUTFStrTest := 'a025014030d125c34d3629dde73304535597a7a06ce6b012686' +
                                    'cc064f9aba29fa943e8d07ce689aa2107f2f6162f71182b4ae1' +
                                    'ab9cfd6ddfb3eaa66a12cc3d01';
  FTestData[ 3].Input            := 'a';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '54ee18b0bbd4dd38a211699f2829793156e5842df502a2a2599' +
                                    '5c6c541f28cc050ff57d4af772dee7cedcc4c34c3b8ec06446c' +
                                    '6657f2f36c2c06464399879b86';
  FTestData[ 4].OutputUTFStrTest := '8d41703489c5399ac0717eb23ec100a5a0ee247948b10f6fab1' +
                                    'be49fec61435a23bf5abc72c65ab30c1132d392cdf49d607e1c' +
                                    'd852cd8c97cf7fc56f50c1321c';
  FTestData[ 4].Input            := 'abc';
  FTestData[ 4].Enabled          := true;

  FTestData[ 5].Output           := '29e158ba336ce7f930115178a6c86019f0f413adb283d8f0798' +
                                    'af06ca0a06d6d6f295a333b1c24bda2f429ac918a3748aef90f' +
                                    '7a2c8bfb084d5f979cf4e7b2b5';
  FTestData[ 5].OutputUTFStrTest := '5a8e0846029ec68f58ee2c38d2539a295a08a3495f63c98edf1' +
                                    '4787ed0be8a3cf7ccc941914b6096e09ba81ac16506718188bf' +
                                    '4b27b4719b44b9f7825946277f';
  FTestData[ 5].Input            := 'message digest';
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := '5ac9757e1407432daf348a972b8ad4a65c1123cf1f9b779c1ae' +
                                    '7ee2d540f30b3cefa8f98dca5fbb42084c5c2f161a7b40eb6b4' +
                                    'a1fc7f9aaab92a4bb6002edc5e';
  FTestData[ 6].OutputUTFStrTest := 'cca11e491b08a42a5c36df20f0c1b883b0f73948d3a1821e554' +
                                    '2f7230afc71ba0cc3dbdcb5da0418777cacee0df131a24a5c16' +
                                    '9a1d41e6cdf1e1d0a917f1952a';
  FTestData[ 6].Input            := 'abcdefghijklmnopqrstuvwxyz';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := 'cae4175f09753de84974cfa968621092fe41ee9de913919c2b4' +
                                    '52e6cb424056721d640e563f628f29dd3bd0030837ae4ac14aa' +
                                    '17308505a92e5f7a92f112be75';
  FTestData[ 7].OutputUTFStrTest := 'f12fddbd9a619288f53f1c94920b24cddbd16a1bd07efebdba0' +
                                    'c9a93fd13c6f8aba44e2b11498a9e8679dc7a4ae50a928c4948' +
                                    '68758bf709c65443886213f789';
  FTestData[ 7].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'e5965b4565b041a0d459610e5e48e944c4830cd16feba02d9d2' +
                                    '63e7da8de6a6b88966709bf28a5328d928312e7a172da4cff72' +
                                    'fe6de02277dae4b1dba49689a2';
  FTestData[ 8].OutputUTFStrTest := 'bf8878187b8fb4dfba01049f3de15714a7ecf48f0fc005cb41a' +
                                    '79ca4755ab6865409e84256953bca76a0592a5f23998f24b847' +
                                    '9d09678c5edc0cd4515ae35444';
  FTestData[ 8].Input            := '12345678901234567890123456789012345678901234567890'+
                                    '123456789012345678901234567890';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '76c8bc5f445140921ceaaed2afce4d0b0722fde3aea20145d9b' +
                                    '14a72d22799f2ebb88446b7b46f4646eb33fc7e6f153183b2fd' +
                                    '9e9a54557f41b10ab633b8b6e1';
  FTestData[ 9].OutputUTFStrTest := '3176130a3ffa3b8c9e904c4a3ca20912885613cdd5cad9c1f16' +
                                    '906e6e0521da5ba1456a93719a48bd51e22ece0b93a2c1ee533' +
                                    '95120946717e9695242fba7036';
  FTestData[ 9].Input            := 'abcdbcdecdefdefgefghfghighijhijk';
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := 'bb6cba9730d6c029c0c15fb7a2aa3597cf9442dad96a676c5ee' +
                                    '9a1d55f1d64d5e0d1ed0e71250ed960a1bd2e065642cfff1c97' +
                                    '6e061bab70d6c54d284eaaefb9';
//  FTestData[10].OutputUTFStrTest := '';
  FTestData[10].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[10].Enabled          := false;

  FTestData[11].Output           := 'bb6cba9730d6c029c0c15fb7a2aa3597cf9442dad96a676c5ee' +
                                    '9a1d55f1d64d5e0d1ed0e71250ed960a1bd2e065642cfff1c97' +
                                    '6e061bab70d6c54d284eaaefb9';
  FTestData[11].OutputUTFStrTest := 'e5df9ba18452dd692fe434fd3427993fb1b33a9ac55a68161e1' +
                                    '17d1f6d01d7e87b78f907208e4432da35d2704d1d04ddc85051' +
                                    'ca892b2854c0908bd146789aa1';
  SetLength(FTestData[11].Input, 1000000);
  FillChar(FTestData[11].Input[low(FTestData[11].Input)], 1000000, 'a');
  FTestData[11].Enabled:= true;
end;

procedure TestTHash_Whirlpool.TearDown;
begin
  FHash_Whirlpool.Free;
  FHash_Whirlpool := nil;
end;

procedure TestTHash_Whirlpool.TestBlockSize;
begin
  CheckEquals(64, FHash_Whirlpool.BlockSize);
end;

procedure TestTHash_Whirlpool.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Whirlpool);
end;

procedure TestTHash_Whirlpool.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Whirlpool);
end;

procedure TestTHash_Whirlpool.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Whirlpool);
end;

procedure TestTHash_Whirlpool.TestDigestSize;
begin
  CheckEquals(64, FHash_Whirlpool.DigestSize);
end;

procedure TestTHash_Whirlpool.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Whirlpool.IsPasswordHash);
end;

procedure TestTHash_Whirlpool.TestCalcStream;
begin
  DoTestCalcStream(FHash_Whirlpool);
end;

procedure TestTHash_Whirlpool.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Whirlpool);
end;

procedure TestTHash_Whirlpool1.SetUp;
begin
  FHash_Whirlpool1 := THash_Whirlpool1.Create;
  SetLength(FTestData, 12);

  FTestData[ 0].Output           := '470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243c' +
                                    'ad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad' +
                                    '32567897dcb5969861049a0f5a';
  FTestData[ 0].OutputUTFStrTest := '470f0409abaa446e49667d4ebe12a14387cedbd10dd17b8243c' +
                                    'ad550a089dc0feea7aa40f6c2aaab71c6ebd076e43c7cfca0ad' +
                                    '32567897dcb5969861049a0f5a';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'ebaa1df2e97113be187eb0303c660f6e643e2c090ef2cda9a2e' +
                                    'a6dcf5002147d1d0e1e9d996e879cef9d26896630a5db3308d5' +
                                    'a0dc235b199c38923be2259e03';
  FTestData[ 1].OutputUTFStrTest := '5777fc1f8467a1c004cd9130439403ccdaa9fdc86092d9cffe3' +
                                    '39e6008612374d04c8fc0c724707feae6f7ceb1e030cabf652a' +
                                    '673da1849b02654af76eee24a7';
  FTestData[ 1].Input            := #$00;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'a8583b83929bd46f0006e8401f87767ff0e23b96cd4cb2fe377' +
                                    '4901ee6eeed91f43ab569fb908122c53a264a35687b40a0590d' +
                                    '83e69fa82724380bae82a1caa0';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := '<\x80>,63!<\x00>';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := 'b290e0e7931025ed37043ad568f0036b40e6bff8f7455868780' +
                                    'f47ef7b5d693e62448029a9351cd85ac29cb0725e4cfeb996a9' +
                                    '2f2b8da8768483ac58ec0e492c';
  FTestData[ 3].OutputUTFStrTest := '528f3f670d4dfed05ff342f36d16b8a5a0d884da737dbc1b55c' +
                                    '2575362b5fbf9df895013bccc3a72dd7d78c157c52609b42633' +
                                    'a48affdd58297f44b3f40c5626';
  FTestData[ 3].Input            := 'a';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '8afc0527dcc0a19623860ef2369d0e25de8ebe2abaa40f598af' +
                                    'af6b07c002ed73e4fc0fc220fd4f54f74b5d6b07aa57764c3db' +
                                    'dcc2cdd919d89fa8155a34b841';
  FTestData[ 4].OutputUTFStrTest := '5e812e973466dde1b43dfcd752ec1828f53ecb0e330f6937311' +
                                    '159d6eded439994ccafa867a034266bc16ce73057343a01742d' +
                                    '8b13053aa1d4ce82f52f312fce';
  FTestData[ 4].Input            := 'abc';
  FTestData[ 4].Enabled          := true;

  FTestData[ 5].Output           := '817eadf8efca5afbc11f71d0814e03a8d569c90f748c8603597' +
                                    'a7a0de3c8d55f528199010218249517b58b14bee52351560875' +
                                    '4b53a3cca35c0865ba5e361431';
  FTestData[ 5].OutputUTFStrTest := '5fb89db25c24f3c3d222302ead771d6c371c8fa0af40f62a422' +
                                    'cf092cf6af6bf0ab4c6707e25c34680bfdbf92973de78d37d9f' +
                                    'af2bed23dd9b27d53ed02ea473';
  FTestData[ 5].Input            := 'message digest';
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := '4afc2b07bddc8417635fcb43e695e16f45e116c226dd84339eb' +
                                    '95c2ccb39e7acbe1af8f7b1f3bd380077e71929498bc9682003' +
                                    '71f9299015434d1df109a0aa1d';
  FTestData[ 6].OutputUTFStrTest := '1925d2d0eaa3e76ed1cd7d95b0bdd03152f9d2193376f6348c0' +
                                    '64fc5115233f88a26610428bea98935464cce2078af9e81ca3f' +
                                    '31bdd5b5c5d5f3775c85569c1f';
  FTestData[ 6].Input            := 'abcdefghijklmnopqrstuvwxyz';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '0f960ec9ab7d0c7e355a423d1ef4911a39797c836a71414276a' +
                                    'feb8fa475dba0c348547143162f3212edf1fb8d8c652a11a579' +
                                    'a399c2dbd837fe8608f5096131';
  FTestData[ 7].OutputUTFStrTest := 'c8176962d4e58e8e6174a3e3eecd1ab012345f3fa04ff06515b' +
                                    'b225bcdfa13ccbe5c53c357534aade7db3a46ff24c6c86bd5d3' +
                                    '465930c5d4ba0b734efcf8b43b';
  FTestData[ 7].Input            := 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '6ae43784c69d01c273bba40f8411495167909e0c1acc241473d' +
                                    '44e27bc8641e646535d38fce20604941988c387c201cff199c8' +
                                    'fa2afbedd036d66202892a7eee';
  FTestData[ 8].OutputUTFStrTest := '0fb6cadc695c10b27f8dc5a591e7856acc8edb22459060dfa28' +
                                    'd9f9532e1f7b2206b8b297f9d89f85570f73439592a45fd6475' +
                                    'd0a83923cead6eb443d3f69bb1';
  FTestData[ 8].Input            := '12345678901234567890123456789012345678901234567890'+
                                    '123456789012345678901234567890';
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '7da3991ff3d40e0beed44b89c83bed5b085cc390a2df47765c9' +
                                    '9ae2ddb0a1e2e094ef0e8b0cf7ba4733afd756ef8eef59b9181' +
                                    '29fe2efe0b00024d6c4e56dc45';
  FTestData[ 9].OutputUTFStrTest := '5586a2f7b714de8301412ff72d7bc8d4def56cece16ce4adc48' +
                                    'b3a6ef5b46ab17c979f8e1aedae3cbf4b74a4ea0e8b02e02032' +
                                    'a782094ff00fea088b78759ab9';
  FTestData[ 9].Input            := 'abcdbcdecdefdefgefghfghighijhijk';
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '0ee18ba7ca7ee091dace6285661eedf819a8fa17620f72aeffe' +
                                    '5aa62c462138b626aa09072a10fcbcfe7f7ff22db2f4d6d1f07' +
                                    '71856c4a7924f9b0e4044d9112';
//  FTestData[10].OutputUTFStrTest := '';
  FTestData[10].Input            := 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
  FTestData[10].Enabled          := false;

  FTestData[11].Output           := '0ee18ba7ca7ee091dace6285661eedf819a8fa17620f72aeffe' +
                                    '5aa62c462138b626aa09072a10fcbcfe7f7ff22db2f4d6d1f07' +
                                    '71856c4a7924f9b0e4044d9112';
  FTestData[11].OutputUTFStrTest := '6449537a67085f0ac0d80956d7d92d0cf0ec48cebde1728ad13' +
                                    'b88decd218a951f6b17303bfc552db14cff4607b4155eae9514' +
                                    '51d19010a7c43802a0495ccd68';
  SetLength(FTestData[11].Input, 1000000);
  FillChar(FTestData[11].Input[low(FTestData[11].Input)], 1000000, 'a');
  FTestData[11].Enabled          := true;
end;

procedure TestTHash_Whirlpool1.TearDown;
begin
  FHash_Whirlpool1.Free;
  FHash_Whirlpool1 := nil;
end;

procedure TestTHash_Whirlpool1.TestBlockSize;
begin
  CheckEquals(64, FHash_Whirlpool1.BlockSize);
end;

procedure TestTHash_Whirlpool1.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Whirlpool1);
end;

procedure TestTHash_Whirlpool1.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Whirlpool1);
end;

procedure TestTHash_Whirlpool1.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Whirlpool1);
end;

procedure TestTHash_Whirlpool1.TestDigestSize;
begin
  CheckEquals(64, FHash_Whirlpool1.DigestSize);
end;

procedure TestTHash_Whirlpool1.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Whirlpool1.IsPasswordHash);
end;

procedure TestTHash_Whirlpool1.TestCalcStream;
begin
  DoTestCalcStream(FHash_Whirlpool1);
end;

procedure TestTHash_Whirlpool1.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Whirlpool1);
end;

procedure TestTHash_Square.SetUp;
begin
  FHash_Square := THash_Square.Create;
  SetLength(FTestData, 9);

  FTestData[ 0].Output           := '417b878eaf7d8ca82414e6e4c4a95149';
  FTestData[ 0].OutputUTFStrTest := '417b878eaf7d8ca82414e6e4c4a95149';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '62148aad7927998c545c6f0e5feca9f0';
  FTestData[ 1].OutputUTFStrTest := 'bb806953f163a83880789c5793df24ff';
  FTestData[ 1].Input            := 'a';
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '931b73d1a404f6f18880068056f6fc12';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := 'ab,c';
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := '2068598052889ea245b4906f621f398c';
  FTestData[ 3].OutputUTFStrTest := '3f1a4493b8bc057a279b9aa38917fb07';
  FTestData[ 3].Input            := 'message digest';
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'fc356316c8a28b7dbfe0ff3fef52bf53';
//  FTestData[ 4].OutputUTFStrTest := '';
  FTestData[ 4].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[ 4].Enabled          := false;

  FTestData[ 5].Output           := 'b8654c7c554f18541bb28794a17f0c09';
//  FTestData[ 5].OutputUTFStrTest := '';
  FTestData[ 5].Input            := 'A,BCDEFGHIJKLMNOPQRS,TUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[ 5].Enabled          := false;

  FTestData[ 6].Output           := '0c004c5b7066610e2a2dd2eecaee3186';
  FTestData[ 6].OutputUTFStrTest := '1b1a00a69f0f19e887574b1f6a792412';
  FTestData[ 6].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := 'c3ba10de37cdec5e99def41475f1df5d';
  FTestData[ 7].OutputUTFStrTest := 'fd99b6eda660c726d0a4e47e13018cfb';
  FTestData[ 7].Input            := 'This test vector intended to detect last zeroized block ' +
                                   'necessity decision error. This block has total length 119 bytes';
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '058a1da3a62f3e6a8ba9135373a089ca';
  FTestData[ 8].OutputUTFStrTest := '9148d4fc4379235a5a065ef88a51cb1d';
  FTestData[ 8].Input            := 'This test vector intended to detect last zeroized block ' +
                                   'necessity decision error. This block has total length 120 bytes.';
  FTestData[ 8].Enabled          := true;
end;

procedure TestTHash_Square.TearDown;
begin
  FHash_Square.Free;
  FHash_Square := nil;
end;

procedure TestTHash_Square.TestDigestSize;
begin
  CheckEquals(16, FHash_Square.DigestSize);
end;

procedure TestTHash_Square.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Square.IsPasswordHash);
end;

procedure TestTHash_Square.TestBlockSize;
begin
  CheckEquals(16, FHash_Square.BlockSize);
end;

procedure TestTHash_Square.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Square);
end;

procedure TestTHash_Square.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Square);
end;

procedure TestTHash_Square.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Square);
end;

procedure TestTHash_Square.TestCalcStream;
begin
  DoTestCalcStream(FHash_Square);
end;

procedure TestTHash_Square.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Square);
end;

procedure TestTHash_Snefru128.SetUp;
begin
  FHash_Snefru128 := THash_Snefru128.Create;
  SetLength(FTestData, 17);

  FTestData[ 0].Output           := '8617f366566a011837f4fb4ba5bedea2';
  FTestData[ 0].OutputUTFStrTest := '8617f366566a011837f4fb4ba5bedea2';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := 'd9fcb3171c097fbba8c8f12aa0906bad';
  FTestData[ 1].OutputUTFStrTest := 'ab3974fcd9f1caa6a2ae226c2974fb0c';
  FTestData[ 1].Input            := #$0A;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := '44ec420ce99c1f62feb66c53c24ae453';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := '1' + #$0A;
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := '7182051aa852ef6fba4b6c9c9b79b317';
  FTestData[ 3].OutputUTFStrTest := '3e34c975f5308c71523b3fc39a3692e6';
  FTestData[ 3].Input            := '12' + #$0A;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'bc3a50af82bf56d6a64732bc7b050a93';
  FTestData[ 4].OutputUTFStrTest := 'e71945a2fcd0f0d992b5d24b6a49547f';
  FTestData[ 4].Input            := '123' + #$0A;
  FTestData[ 4].Enabled          := true;

  FTestData[ 5].Output           := 'c5b8a04985a8eadfb4331a8988752b77';
  FTestData[ 5].OutputUTFStrTest := 'ad32e4eb4cbf5c482194596f28902240';
  FTestData[ 5].Input            := '1234' + #$0A;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'd559a2b62f6f44111324f85208723707';
  FTestData[ 6].OutputUTFStrTest := 'a8b025b7cddd0555b9241dcf16fbd798';
  FTestData[ 6].Input            := '12345' + #$0A;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '6cfb5e8f1da02bd167b01e4816686c30';
  FTestData[ 7].OutputUTFStrTest := '73b7248a11bbb8425863eec60e5d8a43';
  FTestData[ 7].Input            := '123456' + #$0A;
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := '29aa48325f275a8a7a01ba1543c54ba5';
  FTestData[ 8].OutputUTFStrTest := 'd5c92cb71197ee91fd4f347b8fbac655';
  FTestData[ 8].Input            := '1234567' + #$0A;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := 'be862a6b68b7df887ebe00319cbc4a47';
  FTestData[ 9].OutputUTFStrTest := '8b7b3408b144335774eb6c276ded6e00';
  FTestData[ 9].Input            := '12345678' + #$0A;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '6103721ccd8ad565d68e90b0f8906163';
  FTestData[10].OutputUTFStrTest := '1a624aa607071a337558911531a0dde6';
  FTestData[10].Input            := '123456789' + #$0A;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '553d0648928299a0f22a275a02c83b10';
  FTestData[11].OutputUTFStrTest := '94f3567822b3fe5299c0e109dff4fa70';
  FTestData[11].Input            := 'abc';
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := '7840148a66b91c219c36f127a0929606';
//  FTestData[12].OutputUTFStrTest := '';
  FTestData[12].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[12].Enabled          := false;

  FTestData[13].Output           := 'd9204ed80bb8430c0b9c244fe485814a';
  FTestData[13].OutputUTFStrTest := '9a92c0b5e89851f4a5faaa441c250931';
  FTestData[13].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[13].Enabled          := true;

  FTestData[14].Output           := 'dd0d1ab288c3c36671044f41c5077ad6';
  FTestData[14].OutputUTFStrTest := '150c6230252f8497c64f6ccff97928f8';
  FTestData[14].Input            := 'Test message for buffer workflow test(47 bytes)';
  FTestData[14].Enabled          := true;

  FTestData[15].Output           := 'e7054f05bd72d7e86a052153a17c741d';
  FTestData[15].OutputUTFStrTest := '3ab419c9af627272b2e2cdafed2b7150';
  FTestData[15].Input            := 'Test message for buffer workflow test(48 bytes).';
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := '9b34204833422df13c83e10a0c6d080a';
  FTestData[16].OutputUTFStrTest := '906816013ee57f3d2ae1562b9590d82f';
  FTestData[16].Input            := 'Test message for buffer workflow test(49 bytes)..';
  FTestData[16].Enabled          := true;
end;

procedure TestTHash_Snefru128.TearDown;
begin
  FHash_Snefru128.Free;
  FHash_Snefru128 := nil;
end;

procedure TestTHash_Snefru128.TestDigestSize;
begin
  CheckEquals(16, FHash_Snefru128.DigestSize);
end;

procedure TestTHash_Snefru128.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Snefru128.IsPasswordHash);
end;

procedure TestTHash_Snefru128.TestBlockSize;
begin
  CheckEquals(48, FHash_Snefru128.BlockSize);
end;

procedure TestTHash_Snefru128.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Snefru128);
end;

procedure TestTHash_Snefru128.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Snefru128);
end;

procedure TestTHash_Snefru128.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Snefru128);
end;

procedure TestTHash_Snefru128.TestCalcStream;
begin
  DoTestCalcStream(FHash_Snefru128);
end;

procedure TestTHash_Snefru128.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Snefru128);
end;

procedure TestTHash_Snefru256.SetUp;
begin
  FHash_Snefru256 := THash_Snefru256.Create;
  SetLength(FTestData, 14);

  FTestData[ 0].Output           := '8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881';
  FTestData[ 0].OutputUTFStrTest := '8617f366566a011837f4fb4ba5bedea2b892f3ed8b894023d16ae344b2be5881';
  FTestData[ 0].Input            := '';
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '2e02687f0d45d5b9b50cb68c3f33e6843d618a1aca2d06893d3eb4e3026b5732';
  FTestData[ 1].OutputUTFStrTest := 'ea81f0d664c9f14b5af04103212ea129001da9c3c421b6e340bdb9ece6c90244';
  FTestData[ 1].Input            := #$0A;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'bfea4a05a2a2ef15c736d114598a20b9d9bd4d66b661e6b05ecf6a7737bdc58c';
//  FTestData[ 2].OutputUTFStrTest := '';
  FTestData[ 2].Input            := '1' + #$0A;
  FTestData[ 2].Enabled          := false;

  FTestData[ 3].Output           := 'ac677d69761ade3f189c7aef106d5fe7392d324e19cc76d5db4a2c05f2cc2cc5';
  FTestData[ 3].OutputUTFStrTest := 'f3530df84977152b8a38867acf14c9a46cfae162f9543c986a500cf32d5a7359';
  FTestData[ 3].Input            := '12' + #$0A;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := '061c76aa1db4a22c0e42945e26c48499b5400162e08c640be05d3c007c44793d';
  FTestData[ 4].OutputUTFStrTest := '25987aee97eeee4d4e3914e8245ecdfe69e45cbe0e728175cb4411e046091fd4';
  FTestData[ 4].Input            := '123' + #$0A;
  FTestData[ 4].Enabled          := true;

  FTestData[ 5].Output           := '1e87fe1d9c927e9e24be85e3cc73359873541640a6261793ce5a974953113f5e';
  FTestData[ 5].OutputUTFStrTest := 'b76fbfabada71bf38decdd3b4e19ec39292a496dd23c29755c4a96caf77d4b13';
  FTestData[ 5].Input            := '1234' + #$0A;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := '1b59927d85a9349a87796620fe2ff401a06a7ba48794498ebab978efc3a68912';
  FTestData[ 6].OutputUTFStrTest := '6598676a170cf7075cee8b54da5844a824c0e1cb9830773ba9728ca2c65f7fe5';
  FTestData[ 6].Input            := '12345' + #$0A;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '28e9d9bc35032b68faeda88101ecb2524317e9da111b0e3e7094107212d9cf72';
  FTestData[ 7].OutputUTFStrTest := '062cc2b932500825575447e87a9416f38d561b0b3111b36011a9e6ef773cf54b';
  FTestData[ 7].Input            := '123456' + #$0A;
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'f7fff4ee74fd1b8d6b3267f84e47e007f029d13b8af7e37e34d13b469b8f248f';
  FTestData[ 8].OutputUTFStrTest := '45b05d5126783c33b68f9a813cb3010f84cc9c1d6b133391a88ae61b43c89cc5';
  FTestData[ 8].Input            := '1234567' + #$0A;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := 'ee7d64b0102b2205e98926613b200185559d08be6ad787da717c968744e11af3';
  FTestData[ 9].OutputUTFStrTest := '9e614b25cd9d6b260c2fdeb59b1d6de8e8329157aa581a9f63424b4c012bd0df';
  FTestData[ 9].Input            := '12345678' + #$0A;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := '4ca72639e40e9ab9c0c3f523c4449b3911632d374c124d7702192ec2e4e0b7a3';
  FTestData[10].OutputUTFStrTest := '7dde03a5c268df01f5cdc408dc1807a677954e6aaf9ad0d6235809b758ef7691';
  FTestData[10].Input            := '123456789' + #$0A;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '7d033205647a2af3dc8339f6cb25643c33ebc622d32979c4b612b02c4903031b';
  FTestData[11].OutputUTFStrTest := '116509bcc4ec01f1b14d7769241cdb2438073bf9ed2031b11efb52913c0a635c';
  FTestData[11].Input            := 'abc';
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := '9304bb2f876d9c4f54546cf7ec59e0a006bead745f08c642f25a7c808e0bf86e';
//  FTestData[12].OutputUTFStrTest := '';
  FTestData[12].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[12].Enabled          := false;

  FTestData[13].Output           := 'd5fce38a152a2d9b83ab44c29306ee45ab0aed0e38c957ec431dab6ed6bb71b8';
  FTestData[13].OutputUTFStrTest := '5fa0a6e55b18b8db6f17280bf1312f1b9651664a849feecb34fd792c392f0ae6';
  FTestData[13].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[13].Enabled          := true;
end;

procedure TestTHash_Snefru256.TearDown;
begin
  FHash_Snefru256.Free;
  FHash_Snefru256 := nil;
end;

procedure TestTHash_Snefru256.TestDigestSize;
begin
  CheckEquals(32, FHash_Snefru256.DigestSize);
end;

procedure TestTHash_Snefru256.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Snefru256.IsPasswordHash);
end;

procedure TestTHash_Snefru256.TestBlockSize;
begin
  CheckEquals(32, FHash_Snefru256.BlockSize);
end;

procedure TestTHash_Snefru256.TestCalcBuffer;
begin
  DoTestCalcBuffer(FHash_Snefru256);
end;

procedure TestTHash_Snefru256.TestCalcBytes;
begin
  DoTestCalcBytes(FHash_Snefru256);
end;

procedure TestTHash_Snefru256.TestCalcRawByteString;
begin
  DoTestCalcRawByteString(FHash_Snefru256);
end;

procedure TestTHash_Snefru256.TestCalcStream;
begin
  DoTestCalcStream(FHash_Snefru256);
end;

procedure TestTHash_Snefru256.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Snefru256);
end;

procedure TestTHash_Sapphire.SetUp;
begin
  FHash_Sapphire := THash_Sapphire.Create;
  SetLength(FTestData, 19);

  FTestData[ 0].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436a';
  FTestData[ 0].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436a' +
                                    'd29c9fe54b096f54a2a128bb08c9651f' +
                                    '34606520fa7a5ad780e1d9c176234650' +
                                    'ad6af1a70d871d7d63d09af96692775a';
  FTestData[ 0].Input            := '';
  FTestData[ 0].ReqDigSize       := 16;
  FTestData[ 0].Enabled          := true;

  FTestData[ 1].Output           := '4acf17d911781571f053ce82e2f70cce';
  FTestData[ 1].OutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822' +
                                    'c7a6d25ced55ad8ddc81aad5cba2e6d3' +
                                    '7eb8dbc44c70af770ade17ccc224edd2' +
                                    'ddcd93d396a986eb5beac360adcc4df1';
  FTestData[ 1].Input            := 'abc';
  FTestData[ 1].ReqDigSize       := 16;
  FTestData[ 1].Enabled          := true;

  FTestData[ 2].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe5';
  FTestData[ 2].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe5' +
                                    '4b096f54a2a128bb08c9651f34606520fa7a5ad7' +
                                    '80e1d9c176234650ad6af1a70d871d7d63d09af96692775a';
  FTestData[ 2].Input            := '';
  FTestData[ 2].ReqDigSize       := 20;
  FTestData[ 2].Enabled          := true;

  FTestData[ 3].Output           := '4acf17d911781571f053ce82e2f70cce5470f410';
  FTestData[ 3].OutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25c' +
                                    'ed55ad8ddc81aad5cba2e6d37eb8dbc44c70af77' +
                                    '0ade17ccc224edd2ddcd93d396a986eb5beac360adcc4df1';
  FTestData[ 3].Input            := 'abc';
  FTestData[ 3].ReqDigSize       := 20;
  FTestData[ 3].Enabled          := true;

  FTestData[ 4].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54';
  FTestData[ 4].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54' +
                                    'a2a128bb08c9651f34606520fa7a5ad780e1d9c176234650' +
                                    'ad6af1a70d871d7d63d09af96692775a';
  FTestData[ 4].Input            := '';
  FTestData[ 4].ReqDigSize       := 24;
  FTestData[ 4].Enabled          := true;

  FTestData[ 5].Output           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a6';
  FTestData[ 5].OutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8d' +
                                    'dc81aad5cba2e6d37eb8dbc44c70af770ade17ccc224edd2' +
                                    'ddcd93d396a986eb5beac360adcc4df1';
  FTestData[ 5].Input            := 'abc';
  FTestData[ 5].ReqDigSize       := 24;
  FTestData[ 5].Enabled          := true;

  FTestData[ 6].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb';
  FTestData[ 6].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb'+
                                    '08c9651f34606520fa7a5ad780e1d9c176234650ad6af1a70d871d7d' +
                                    '63d09af96692775a';
  FTestData[ 6].Input            := '';
  FTestData[ 6].ReqDigSize       := 28;
  FTestData[ 6].Enabled          := true;

  FTestData[ 7].Output           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814';
  FTestData[ 7].OutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5' +
                                    'cba2e6d37eb8dbc44c70af770ade17ccc224edd2ddcd93d396a986eb' +
                                    '5beac360adcc4df1';
  FTestData[ 7].Input            := 'abc';
  FTestData[ 7].ReqDigSize       := 28;
  FTestData[ 7].Enabled          := true;

  FTestData[ 8].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f';
  FTestData[ 8].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f' +
                                    '34606520fa7a5ad780e1d9c176234650ad6af1a70d871d7d63d09af96692775a';
  FTestData[ 8].Input            := '';
  FTestData[ 8].ReqDigSize       := 32;
  FTestData[ 8].Enabled          := true;

  FTestData[ 9].Output           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814b6df1f32';
  FTestData[ 9].OutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5cba2e6d3' +
                                    '7eb8dbc44c70af770ade17ccc224edd2ddcd93d396a986eb5beac360adcc4df1';
  FTestData[ 9].Input            := 'abc';
  FTestData[ 9].ReqDigSize       := 32;
  FTestData[ 9].Enabled          := true;

  FTestData[10].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520';
  FTestData[10].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520' +
                                    'fa7a5ad780e1d9c176234650ad6af1a70d871d7d63d09af96692775a';
  FTestData[10].Input            := '';
  FTestData[10].ReqDigSize       := 36;
  FTestData[10].Enabled          := true;

  FTestData[11].Output           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814b6df1f327c766773';
  FTestData[11].OutputUTFStrTest := '9c7d13f4c388cd4dea2b3f513dc08822c7a6d25ced55ad8ddc81aad5cba2e6d37eb8dbc4' +
                                    '4c70af770ade17ccc224edd2ddcd93d396a986eb5beac360adcc4df1';
  FTestData[11].Input            := 'abc';
  FTestData[11].ReqDigSize       := 36;
  FTestData[11].Enabled          := true;

  FTestData[12].Output           := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520fa7a5ad7';
  FTestData[12].OutputUTFStrTest := 'c1e0df6ce706a32fb7b25b7ac55f436ad29c9fe54b096f54a2a128bb08c9651f34606520fa7a5ad7' +
                                    '80e1d9c176234650ad6af1a70d871d7d63d09af96692775a';
  FTestData[12].Input            := '';
  FTestData[12].ReqDigSize       := 40;
  FTestData[12].Enabled          := true;

  FTestData[13].Output           := '8b3763c9e423995743a702a37cc4a82c9771c7ac04fe44990d2cf64a311715406a59cf62b0b4edc9';
  FTestData[13].OutputUTFStrTest := 'a947fdf3a224bcd948c426cec358e84c8468ff42af47dd558979953ee426213ac2f415b0c3c9d476' +
                                    'ad8739529ed87335e5bdb740809b246cbc41b6b117d2fb02';
  FTestData[13].Input            := 'a';
  FTestData[13].ReqDigSize       := 40;
  FTestData[13].Enabled          := true;

  FTestData[14].Output           := '4acf17d911781571f053ce82e2f70cce5470f410b717b9a699063814b6df1f327c766773fc59830b';
//  FTestData[14].OutputUTFStrTest := '';
  FTestData[14].Input            := 'ab,c';
  FTestData[14].ReqDigSize       := 40;
  FTestData[14].Enabled          := false;

  FTestData[15].Output           := 'e0affc0f16c9303c9938dbc9b1e6be3a3dcb75a2879ef8227fdd42595980793c94e7d3e33ce0a20a';
  FTestData[15].OutputUTFStrTest := 'f8ddc0058786d1094b005901927e6743ec8a46ba69a8c0e3821086510dfc338ec839fb729a733c3b' +
                                    '53d26592ec0395903db16fdc06283024146f5259616feb1f';
  FTestData[15].Input            := 'message digest';
  FTestData[15].ReqDigSize       := 40;
  FTestData[15].Enabled          := true;

  FTestData[16].Output           := '23b86cf1a67c6870b90e594be9b4eda4c3862036edf1efb03c86863c274585cf5837429f1ff6f4b0';
//  FTestData[16].OutputUTFStrTest := '';
  FTestData[16].Input            := 'abcdefghijklm,nopqrstuvwxyz';
  FTestData[16].ReqDigSize       := 40;
  FTestData[16].Enabled          := false;

  FTestData[17].Output           := '341530ae3c1f715197847eddd38b4f58cc9a13c3e65f890772c9c561b103d2bf41340dff2af0335f';
//  FTestData[17].OutputUTFStrTest := '';
  FTestData[17].Input            := 'A,BCDEFGHIJKLMNOPQRS,TUVWXYZabcdefghijklmnopqrstuvwxyz012345678,9';
  FTestData[17].ReqDigSize       := 40;
  FTestData[17].Enabled          := false;

  FTestData[18].Output           := '5bb5a1bd1ad4974042aa74992489fbdec857212a29cedc67b1fc79ddc9f139c3f52044be4e6f8588';
  FTestData[18].OutputUTFStrTest := '87b0a006a73261011c4df04dc164216cfe566e54f92f161fec529c3cc956929955b1dc1cbe0215fa' +
                                    '29f6718f69bdee4de5bba6dece94bb8e7861b917c6e67632';
  FTestData[18].Input            := '12345678901234567890123456789012345678901234567890123456789012345678901234567890';
  FTestData[18].ReqDigSize       := 40;
  FTestData[18].Enabled          := true;
end;

procedure TestTHash_Sapphire.TearDown;
begin
  FHash_Sapphire.Free;
  FHash_Sapphire := nil;
end;

procedure TestTHash_Sapphire.TestDigestSize;
begin
  CheckEquals(64, FHash_Sapphire.DigestSize);
end;

procedure TestTHash_Sapphire.TestIsPasswordHash;
begin
  CheckNotEquals(true, FHash_Sapphire.IsPasswordHash);
end;

procedure TestTHash_Sapphire.TestBlockSize;
begin
  CheckEquals(1, FHash_Sapphire.BlockSize);
end;

procedure TestTHash_Sapphire.TestCalcBuffer;
var
  i   : Integer;
  Buf : TBytes;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      Buf := BytesOf(FTestData[i].Input);
      FHash_Sapphire.RequestedDigestSize := FTestData[i].ReqDigSize;

      if Length(FTestData[i].Input) > 0 then
        CheckEquals(FTestData[i].Output,
                    BytesToRawString(TFormat_HEXL.Encode(FHash_Sapphire.CalcBuffer(Buf[0],
                                                         Length(Buf)))),
                    'Index: ' + IntToStr(i))
      else
        CheckEquals(FTestData[i].Output,
                    BytesToRawString(TFormat_HEXL.Encode(FHash_Sapphire.CalcBuffer(Buf,
                                                         Length(Buf)))),
                                     'Index: ' + IntToStr(i));
    end;
end;

procedure TestTHash_Sapphire.TestCalcBytes;
var
  i : Integer;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      FHash_Sapphire.RequestedDigestSize := FTestData[i].ReqDigSize;

      CheckEquals(FTestData[i].Output,
                  BytesToRawString(TFormat_HEXL.Encode(FHash_Sapphire.CalcBytes(BytesOf(FTestData[i].Input)))));
    end;
end;

procedure TestTHash_Sapphire.TestCalcRawByteString;
var
  i : Integer;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      FHash_Sapphire.PaddingByte := FTestData[i].PaddingByte;
      FHash_Sapphire.RequestedDigestSize := FTestData[i].ReqDigSize;

      CheckEquals(FTestData[i].Output,
                  FHash_Sapphire.CalcString(FTestData[i].Input, TFormat_HEXL));
    end;
end;

procedure TestTHash_Sapphire.TestCalcStream;
var
  s    : TMemoryStream;
  i    : Integer;
  Buf  : TBytes;
  Hash : TBytes;
begin
  s := TMemoryStream.Create;

  try
    for i := Low(FTestData) to High(FTestData) do
      if FTestData[i].Enabled then
      begin
        FHash_Sapphire.RequestedDigestSize := FTestData[i].ReqDigSize;
        Buf := BytesOf(FTestData[i].Input);
        s.Clear;
        s.Write(Buf, Length(Buf));
        s.Position := 0;

        FHash_Sapphire.CalcStream(s, Length(Buf), Hash);

        CheckEquals(FTestData[i].Output,
                    BytesToRawString(TFormat_HEXL.Encode(Hash)));
      end;
  finally
    s.Free;
  end;
end;

procedure TestTHash_Sapphire.TestCalcUnicodeString;
begin
  DoTestCalcUnicodeString(FHash_Sapphire);
end;

{ THash_TestBase }

procedure THash_TestBase.DoTestCalcBuffer(HashClass: TDECHash);
var
  i   : Integer;
  Buf : TBytes;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      Buf := BytesOf(RawByteString(FTestData[i].Input));
      HashClass.PaddingByte := FTestData[i].PaddingByte;

      if Length(FTestData[i].Input) > 0 then
        CheckEquals(FTestData[i].Output,
                    BytesToRawString(TFormat_HEXL.Encode(HashClass.CalcBuffer(Buf[0], Length(Buf)))),
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].Output) + '> but was: <' +
                    string(BytesToRawString(TFormat_HEXL.Encode(HashClass.CalcBuffer(Buf[0], Length(Buf))))) + '>')

      else
        CheckEquals(FTestData[i].Output,
                    BytesToRawString(TFormat_HEXL.Encode(HashClass.CalcBuffer(Buf, Length(Buf)))),
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].Output) + '> but was: <' +
                    string(BytesToRawString(TFormat_HEXL.Encode(HashClass.CalcBuffer(Buf, Length(Buf))))) + '>');
    end;
end;

procedure THash_TestBase.DoTestCalcBytes(HashClass: TDECHash);
var
  i : Integer;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      HashClass.PaddingByte := FTestData[i].PaddingByte;

      CheckEquals(FTestData[i].Output,
                  BytesToRawString(TFormat_HEXL.Encode(HashClass.CalcBytes(BytesOf(RawByteString(FTestData[i].Input))))),
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].Output) + '> but was: <' +
                  string(BytesToRawString(TFormat_HEXL.Encode(HashClass.CalcBytes(BytesOf(RawByteString(FTestData[i].Input)))))) + '>');
    end;
end;

procedure THash_TestBase.DoTestCalcStream(HashClass: TDECHash);
var
  s    : TMemoryStream;
  i    : Integer;
  Buf  : TBytes;
  Hash : TBytes;
begin
  s := TMemoryStream.Create;

  try
    for i := Low(FTestData) to High(FTestData) do
      if FTestData[i].Enabled then
      begin
        Buf := BytesOf(FTestData[i].Input);
        s.Clear;
        s.Write(Buf, Length(Buf));
        s.Position := 0;

        HashClass.PaddingByte := FTestData[i].PaddingByte;
        HashClass.CalcStream(s, Length(Buf), Hash);

        CheckEquals(FTestData[i].Output,
                    BytesToRawString(TFormat_HEXL.Encode(Hash)),
                    'Index: ' + IntToStr(i) + ' - expected: <' +
                    string(FTestData[i].Output) + '> but was: <' +
                    string(BytesToRawString(TFormat_HEXL.Encode(Hash))) + '>');
      end;
  finally
    s.Free;
  end;
end;

procedure THash_TestBase.DoTestCalcUnicodeString(HashClass: TDECHash);
var
  i      : Integer;
  InpStr : string;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      InpStr := string(FTestData[i].Input);

      HashClass.PaddingByte := FTestData[i].PaddingByte;

      CheckEquals(FTestData[i].OutputUTFStrTest,
                  BytesToRawString(TFormat_HEXL.Encode(System.SysUtils.BytesOf(HashClass.CalcString(InpStr)))),
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].OutputUTFStrTest) + '> but was: <' +
                  string(BytesToRawString(TFormat_HEXL.Encode(System.SysUtils.BytesOf(HashClass.CalcString(InpStr))))) + '>');
    end;
end;

procedure THash_TestBase.DoTestCalcRawByteString(HashClass: TDECHash);
var
  i : Integer;
begin
  for i := Low(FTestData) to High(FTestData) do
    if FTestData[i].Enabled then
    begin
      HashClass.PaddingByte := FTestData[i].PaddingByte;
      CheckEquals(FTestData[i].Output,
                  HashClass.CalcString(FTestData[i].Input, TFormat_HEXL),
                  'Index: ' + IntToStr(i) + ' - expected: <' +
                  string(FTestData[i].Output) + '> but was: <' +
                  string(HashClass.CalcString(FTestData[i].Input, TFormat_HEXL)) + '>');
    end;
end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTests('DECHash', [TestTHash_MD2.Suite,
                            TestTHash_MD4.Suite,
                            TestTHash_MD5.Suite,
                            TestTHash_RipeMD128.Suite,
                            TestTHash_RipeMD160.Suite,
                            TestTHash_RipeMD256.Suite,
                            TestTHash_RipeMD320.Suite,
                            TestTHash_SHA.Suite,
                            TestTHash_SHA256.Suite,
                            TestTHash_SHA384.Suite,
                            TestTHash_SHA512.Suite,
                            TestTHash_Haval128.Suite,
                            TestTHash_Haval160.Suite,
                            TestTHash_Haval192.Suite,
                            TestTHash_Haval224.Suite,
                            TestTHash_Haval256.Suite,
                            TestTHash_Tiger_3Rounds.Suite,
                            TestTHash_Tiger_4Rounds.Suite,
                            TestTHash_Panama.Suite,
                            TestTHash_Whirlpool.Suite,
                            TestTHash_Whirlpool1.Suite,
                            TestTHash_Square.Suite,
                            TestTHash_Snefru128.Suite,
                            TestTHash_Snefru256.Suite,
                            TestTHash_Sapphire.Suite]);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestTHash_MD2);
  TDUnitX.RegisterTestFixture(TestTHash_MD4);
  TDUnitX.RegisterTestFixture(TestTHash_MD5);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD128);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD160);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD256);
  TDUnitX.RegisterTestFixture(TestTHash_RipeMD320);
  TDUnitX.RegisterTestFixture(TestTHash_SHA);
  TDUnitX.RegisterTestFixture(TestTHash_SHA256);
  TDUnitX.RegisterTestFixture(TestTHash_SHA384);
  TDUnitX.RegisterTestFixture(TestTHash_SHA512);
  TDUnitX.RegisterTestFixture(TestTHash_Haval128);
  TDUnitX.RegisterTestFixture(TestTHash_Haval160);
  TDUnitX.RegisterTestFixture(TestTHash_Haval192);
  TDUnitX.RegisterTestFixture(TestTHash_Haval224);
  TDUnitX.RegisterTestFixture(TestTHash_Haval256);
  TDUnitX.RegisterTestFixture(TestTHash_Tiger_3Rounds);
  TDUnitX.RegisterTestFixture(TestTHash_Tiger_4Rounds);
  TDUnitX.RegisterTestFixture(TestTHash_Panama);
  TDUnitX.RegisterTestFixture(TestTHash_Whirlpool);
  TDUnitX.RegisterTestFixture(TestTHash_Whirlpool1);
  TDUnitX.RegisterTestFixture(TestTHash_Square);
  TDUnitX.RegisterTestFixture(TestTHash_Snefru128);
  TDUnitX.RegisterTestFixture(TestTHash_Snefru256);
  TDUnitX.RegisterTestFixture(TestTHash_Sapphire);
  {$ENDIF}
end.
