{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2020 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
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
unit TestDECCipherFormats;

// Needs to be included before any other statements
{$I defines.inc}

interface

uses
  {$IFNDEF DUnitX}
  TestFramework,
  {$ENDIF}
  {$IFDEF DUnitX}
  DUnitX.TestFramework,DUnitX.DUnitCompatibility,
  {$ENDIF}

  Classes, SysUtils, DECCipherBase, DECCiphers;

type
  /// <summary>
  ///   All known testvectors use the same filler byte and the same cmCTSx mode
  /// </summary>
  TCipherTestData = record
    InputData  : RawByteString;
    OutputData : RawByteString;

    Key        : RawByteString;
    InitVector : RawByteString;
    Filler     : Byte;
    Mode       : TCipherMode;
  end;

  /// <summary>
  ///   base class for all cipher mode tests to make them more independent of
  ///   the actually tested algorithm
  /// </summary>
  TestTDECCipherFormatsBase = class(TTestCase)
  strict protected
    FCipher        : TDECCipher;
    FTestData      : array of TCipherTestData;

    /// <summary>
    ///   Initialize the cipher alrorithm with the initial values for a
    ///   single test
    /// </summary>
    /// <param name="Cipher">
    ///   Instance which shall be initialized with the test data given
    /// </param>
    /// <param name="TestData">
    ///   Data used to initialize the instance
    /// </param>
    procedure Init(Cipher: TDECCipher; TestData: TCipherTestData);
    /// <summary>
    ///   Ensures that a given key is not longer then the KeySize passed
    /// </summary>
    /// <param name="Key">
    ///   Key to be checked. if it is longer than KeySize it will be cut off.
    /// </param>
    /// <param name="KeySize">
    ///   Maximum size of a key for the given cipher algorithm
    /// </param>
    procedure LimitKeyLength(var Key:RawByteString; KeySize: Integer);

    procedure DoTestEncodeBytes(Cipher: TDECCipher);
  end;

  // Test methods for class TDECClassList
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherFormats = class(TestTDECCipherFormatsBase)
  strict private
    FCipherTwoFish : TCipher_Twofish;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestEncodeBytes;
    procedure TestDecodeBytes;

    procedure TestEncodeStream;
    procedure TestDecodeStream;

// Currently commented out because it would require a file as external dependency
//    procedure TestEncodeFile(const SourceFileName, DestFileName: string;
//                             const Progress: IDECProgress = nil);
//    procedure TestDecodeFile(const SourceFileName, DestFileName: string;
//                             const Progress: IDECProgress = nil);

    procedure TestEncodeStringToBytes;
    procedure TestEncodeRawByteStringToBytes;

    procedure TestEncodeStringToString;
    procedure TestEncodeRawByteStringToString;

    procedure TestDecodeStringToBytes;
    procedure TestDecodeRawByteStringToBytes;

    procedure TestDecodeStringToString;
    procedure TestDecodeRawByteStringToString;

{$IFNDEF NEXTGEN}
    procedure TestEncodeAnsiStringToBytes;
    procedure TestEncodeAnsiStringToString;

    procedure TestDecodeAnsiStringToBytes;
    procedure TestDecodeAnsiStringToString;

    procedure TestEncodeWideStringToBytes;
    procedure TestEncodeWideStringToString;

    procedure TestDecodeWideStringToBytes;
    procedure TestDecodeWideStringToString;
{$ENDIF}
  end;

implementation

uses
  DECBaseClass, DECFormat;

procedure TestTDECCipherFormatsBase.DoTestEncodeBytes(Cipher: TDECCipher);
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    Init(Cipher, FTestData[i]);

    result := Cipher.EncodeBytes(BytesOf(FTestData[i].InputData));

    CheckEquals(FTestData[i].OutputData,
                StringOf(TFormat_HexL.Encode(result)),
                'Fehler in TestEncodeBytes ' + i.ToString);
  end;

end;

procedure TestTDECCipherFormatsBase.Init(Cipher: TDECCipher; TestData: TCipherTestData);
begin
  LimitKeyLength(TestData.Key, Cipher.Context.KeySize);

  Cipher.Mode := TestData.Mode;
  Cipher.Init(BytesOf(TestData.Key),
                      BytesOf(TestData.InitVector),
                      TestData.Filler);
end;

procedure TestTDECCipherFormatsBase.LimitKeyLength(var Key: RawByteString;
  KeySize: Integer);
begin
  if Length(Key) > KeySize then
    Delete(Key, KeySize + 1, length(Key));
end;

{ TestTDECCipherFormats }

procedure TestTDECCipherFormats.TestDecodeRawByteStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStringToBytes;
begin

end;

procedure TestTDECCipherFormats.SetUp;
begin
  FCipherTwoFish := TCipher_Twofish.Create;

  SetLength(FTestData, 1);

  FTestData[0].OutputData  := 'e81674f9bc69442188c949bb52e1e47874171177e99dbbe9880875094f8dfe21';
  FTestData[0].InputData   := TFormat_ESCAPE.Decode('\x30\x44\xED\x6E\x45\xA4' +
                                                    '\x96\xF5\xF6\x35\xA2\xEB' +
                                                    '\x3D\x1A\x5D\xD6\xCB\x1D' +
                                                    '\x09\x82\x2D\xBD\xF5\x60' +
                                                    '\xC2\xB8\x58\xA1\x91\xF9' +
                                                    '\x81\xB1');

  FTestData[0].Key        := 'TCipher_Twofish';
  FTestData[0].InitVector := '';
  FTestData[0].Filler     := $FF;
  FTestData[0].Mode       := cmCTSx;
end;

procedure TestTDECCipherFormats.TearDown;
begin
  FCipherTwoFish.Free;
end;

procedure TestTDECCipherFormats.TestDecodeAnsiStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeAnsiStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeRawByteStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStream;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStringToString;
begin

end;

procedure TestTDECCipherFormats.TestDecodeWideStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeWideStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeAnsiStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeAnsiStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeBytes;
var
  i      : Integer;
  result : TBytes;
begin
  for i := 0 to High(FTestData) do
  begin
    Init(FCipherTwoFish, FTestData[i]);

    result := FCipherTwoFish.EncodeBytes(BytesOf(FTestData[i].InputData));

    CheckEquals(FTestData[i].OutputData,
                StringOf(TFormat_HexL.Encode(result)),
                'Fehler in TestEncodeBytes ' + i.ToString);
  end;

{ TODO :
Change to use DoTestEncodeBytes but that needs to be
passed an init method as calling that one on the TDECCipher
level leads to an assertion later on }
//begin
//  DoTestEncodeBytes(FCipherTwoFish);
end;

procedure TestTDECCipherFormats.TestEncodeRawByteStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeRawByteStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeStream;
begin

end;

procedure TestTDECCipherFormats.TestEncodeStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeStringToString;
begin

end;

procedure TestTDECCipherFormats.TestEncodeWideStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestEncodeWideStringToString;
begin

end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTest(TestTDECCipherFormats.Suite);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestTDECCipherFormats);
  {$ENDIF}
end.
