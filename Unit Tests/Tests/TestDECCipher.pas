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
unit TestDECCipher;

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
  DECBaseClass, DECCipherBase, DECCiphers, Classes, SysUtils,
  DECUtil, DECFormatBase, DECFormat;

type
  // Testmethoden für Klasse TCipher_Null
  TestTCipher_Null = class(TTestCase)
  strict private
    FCipher_Null: TCipher_Null;
  private
  public
    procedure SetUp; override;
    procedure TearDown; override;
    procedure TestClassByName;
  end;

  // A function with these parameters has to be passed to DoTestEncode/Decode to
  // make that one generic
  TEncodeDecodeFunc = function (const Source: RawByteString; Format: TDECFormatClass = nil): TBytes of Object;

  // All known testvectors use the same filler byte and the same cmCTSx mode
  TCipherTestData = record
    InputData  : RawByteString;
    OutputData : RawByteString;

    Key        : RawByteString;
    InitVector : RawByteString;
    Filler     : Byte;
    Mode       : TCipherMode;
  end;

  /// <summary>
  ///   Init method called before conducting a test. Sets up the concrete
  ///   cipher password, mode, initialization vector etc.
  /// </summary>
  /// <param name="TestData">
  ///   Record with the data for the current test, including encryption key,
  ///   initialization vector etc.
  /// </param>
  TInitProc = procedure(TestData: TCipherTestData) Of Object;
  /// <summary>
  ///   Caqllback method for cleaning up after each test
  /// </summary>
  TDoneProc = procedure of Object;

  // Basic class all Cipher test classes should inherit from
  TCipherBasis = class(TTestCase)
  strict protected
    FTestData : array of TCipherTestData;
    /// <summary>
    ///   FTestData gets put into this memory stream in tests which test the
    ///   stream oriented encryption/decryption methods
    /// </summary>
    FTestStream : TMemoryStream;

    /// <summary>
    ///   Converts a test vector with the follwing syntax to a byte array:
    ///   \x30\x31\x41 where \ is the delimiter and x means that the following
    ///   two chars are the hex ordinal number of an ANSI char
    /// </summary>
    function  ConvertHexVectorToBytes(Vector: string): TBytes;

    /// <summary>
    ///   Ensures that a given key is not longer then the KeySize passed
    /// </summary>
    /// <param name="Key">
    ///   Key to be checked. if it is longer than KeySize it will be cut off.
    /// </param>
    /// <param name="KeySize">
    ///   Here the length of a key for the cipher algorithm tested shall be passed
    /// </param>
    procedure LimitKeyLength(var Key:RawByteString; KeySize: Integer);

    procedure DoTestEncode(EncodeFunct: TEncodeDecodeFunc; InitProc: TInitProc; DoneProc: TDoneProc);
    procedure DoTestDecode(DecodeFunct: TEncodeDecodeFunc; InitProc: TInitProc; DoneProc: TDoneProc);
  end;

  // Testmethoden für Klasse TDECCipher
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipher = class(TCipherBasis)
  strict private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestIsClassListCreated;
  end;

  // Testmethoden für Klasse TCipher_Blowfish
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Blowfish = class(TCipherBasis)
  strict private
    FCipher_Blowfish: TCipher_Blowfish;
  private
  public
    procedure SetUp; override;
    procedure TearDown; override;

    procedure Init(TestData: TCipherTestData);
    procedure Done;
  published
    procedure TestContext;
    procedure TestEncode;
    procedure TestDecode;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Twofish
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Twofish = class(TCipherBasis)
  strict private
    FCipher_Twofish: TCipher_Twofish;
  private
  public
    procedure SetUp; override;
    procedure TearDown; override;

    procedure Init(TestData: TCipherTestData);
    procedure Done;
  published
    procedure TestContext;
    procedure TestEncode;
    procedure TestDecode;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_IDEA
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_IDEA = class(TCipherBasis)
  strict private
    FCipher_IDEA: TCipher_IDEA;
  private
    procedure Init(TestData: TCipherTestData);
    procedure Done;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestEncode;
    procedure TestDecode;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Cast256
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Cast256 = class(TCipherBasis)
  strict private
    FCipher_Cast256: TCipher_Cast256;
  private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Mars
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Mars = class(TCipherBasis)
  strict private
    FCipher_Mars: TCipher_Mars;
  private
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_RC4
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_RC4 = class(TCipherBasis)
  strict private
    FCipher_RC4: TCipher_RC4;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_RC6
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_RC6 = class(TCipherBasis)
  strict private
    FCipher_RC6: TCipher_RC6;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Square
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Square = class(TCipherBasis)
  strict private
    FCipher_Square: TCipher_Square;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_SCOP
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_SCOP = class(TCipherBasis)
  strict private
    FCipher_SCOP: TCipher_SCOP;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Sapphire
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Sapphire = class(TCipherBasis)
  strict private
    FCipher_Sapphire: TCipher_Sapphire;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_1DES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_1DES = class(TCipherBasis)
  strict private
    FCipher_1DES: TCipher_1DES;
  public
    procedure SetUp; override;
    procedure TearDown; override;

    procedure Init(TestData: TCipherTestData);
    procedure Done;
  published
    procedure TestContext;
    procedure TestEncode;
    procedure TestDecode;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_2DES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_2DES = class(TCipherBasis)
  strict private
    FCipher_2DES: TCipher_2DES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_3DES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_3DES = class(TCipherBasis)
  strict private
    FCipher_3DES: TCipher_3DES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_2DDES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_2DDES = class(TCipherBasis)
  strict private
    FCipher_2DDES: TCipher_2DDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_3DDES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_3DDES = class(TCipherBasis)
  strict private
    FCipher_3DDES: TCipher_3DDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_3TDES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_3TDES = class(TCipherBasis)
  strict private
    FCipher_3TDES: TCipher_3TDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_3Way
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_3Way = class(TCipherBasis)
  strict private
    FCipher_3Way: TCipher_3Way;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Cast128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Cast128 = class(TCipherBasis)
  strict private
    FCipher_Cast128: TCipher_Cast128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Gost
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Gost = class(TCipherBasis)
  strict private
    FCipher_Gost: TCipher_Gost;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Misty
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Misty = class(TCipherBasis)
  strict private
    FCipher_Misty: TCipher_Misty;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_NewDES
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_NewDES = class(TCipherBasis)
  strict private
    FCipher_NewDES: TCipher_NewDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Q128
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Q128 = class(TCipherBasis)
  strict private
    FCipher_Q128: TCipher_Q128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_RC2
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_RC2 = class(TCipherBasis)
  strict private
    FCipher_RC2: TCipher_RC2;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_RC5
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_RC5 = class(TCipherBasis)
  strict private
    FCipher_RC5: TCipher_RC5;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_SAFER
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_SAFER = class(TCipherBasis)
  strict private
    FCipher_SAFER: TCipher_SAFER;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Shark
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Shark = class(TCipherBasis)
  strict private
    FCipher_Shark: TCipher_Shark;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_Skipjack
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_Skipjack = class(TCipherBasis)
  strict private
    FCipher_Skipjack: TCipher_Skipjack;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_TEA
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_TEA = class(TCipherBasis)
  strict private
    FCipher_TEA: TCipher_TEA;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

  // Testmethoden für Klasse TCipher_XTEA
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTCipher_XTEA = class(TCipherBasis)
  strict private
    FCipher_XTEA: TCipher_XTEA;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestClassByName;
  end;

implementation

const
  cZeroBlock8  = #$00#$00#$00#$00#$00#$00#$00#$00;
  cFFBlock8    = 'FFFFFFFFFFFFFFFF';
  cZeroBlock16 = #$00#$00#$00#$00#$00#$00#$00#$00#$00#$00#$00#$00#$00#$00#$00#$00;
  cFFBlock16   = 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF';

//procedure TestTDECCipher.SetUp;
//begin
//  FDECCipher := TDECCipher.Create;
//end;
//
//procedure TestTDECCipher.TearDown;
//begin
//  FDECCipher.Free;
//  FDECCipher := nil;
//end;
//
//procedure TestTDECCipher.TestContext;
//var
//  ReturnValue: TCipherContext;
//begin
//  ReturnValue := FDECCipher.Context;
//  // TODO: Methodenergebnisse prüfen
//end;
//
//procedure TestTDECCipher.TestInit1;
//var
//  IFiller: Byte;
//  IVector: TArray<System.Byte>;
//  Key: TArray<System.Byte>;
//begin
//  // TODO: Methodenaufrufparameter einrichten
//  FDECCipher.Init(Key, IVector, IFiller);
//  // TODO: Methodenergebnisse prüfen
//end;
//
//procedure TestTDECCipher.TestEncodeBytes;
//var
//  ReturnValue: TBytes;
//  Format: TDECFormatClass;
//  Source: TBytes;
//begin
//  // TODO: Methodenaufrufparameter einrichten
//  ReturnValue := FDECCipher.EncodeBytes(Source, Format);
//  // TODO: Methodenergebnisse prüfen
//end;
//
//procedure TestTDECCipher.TestDecodeBytes;
//var
//  ReturnValue: TBytes;
//  Format: TDECFormatClass;
//  Source: TBytes;
//begin
//  // TODO: Methodenaufrufparameter einrichten
//  ReturnValue := FDECCipher.DecodeBytes(Source, Format);
//  // TODO: Methodenergebnisse prüfen
//end;

procedure TestTCipher_Null.SetUp;
begin
  FCipher_Null := TCipher_Null.Create;
end;

procedure TestTCipher_Null.TearDown;
begin
  FCipher_Null.Free;
  FCipher_Null := nil;
end;

procedure TestTCipher_Null.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Null.ClassByName('TCipher_Null');
  CheckEquals(TCipher_Null, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Blowfish.Done;
begin
  FCipher_Blowfish.Done;
end;

procedure TestTCipher_Blowfish.Init(TestData: TCipherTestData);
var
  Password: RawByteString;
begin
  Password := 'TCipher_Blowfish';
  if Length(Password) > FCipher_Blowfish.Context.KeySize then
    Delete(Password, FCipher_Blowfish.Context.KeySize, length(Password));

  FCipher_Blowfish.Mode := cmCTSx;
//  FCipher_Blowfish.Init(Password, '', $FF);
  FCipher_Blowfish.Init(BytesOf(Password), BytesOf(#$FF#$FF#$FF#$FF#$FF#$FF#$FF#$FF), $FF);
end;

procedure TestTCipher_Blowfish.SetUp;
var
  Password: RawByteString;
  Data : TBytes;
begin
  FCipher_Blowfish      := TCipher_Blowfish.Create;
//  FCipher_Blowfish.Context.

//  Password := 'TCipher_Blowfish';
//  if Length(Password) > FCipher_Blowfish.Context.KeySize then
//    Delete(Password, FCipher_Blowfish.Context.KeySize, length(Password));
//
//  FCipher_Blowfish.Mode := cmCTSx;
//  FCipher_Blowfish.Init(Password, '', $FF);

  SetLength(FTestData, 1);

  Data := System.SysUtils.BytesOf('\x30\x44\xED\x6E\x45\xA4\x96\xF5\xF6\x35\xA2\xEB' +
                                  '\x3D\x1A\x5D\xD6\xCB\x1D\x09\x82\x2D\xBD\xF5\x60' +
                                  '\xC2\xB8\x58\xA1\x91\xF9\x81\xB1');

  FTestData[0].InputData  := RawByteString(StringOf(TFormat_ESCAPE.Decode(Data)));
  FTestData[0].OutputData := '1971cacd2b9c8529da8147b7ebce16c6910e1dc840123e3570edbc964c13d0b8';
end;

procedure TestTCipher_Blowfish.TearDown;
begin
  FCipher_Blowfish.Free;
  FCipher_Blowfish := nil;
end;

procedure TestTCipher_Blowfish.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Blowfish.Context;

  CheckEquals(  56,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals(4168,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Blowfish.TestDecode;
begin
//  DoTestDecode(FCipher_Blowfish.DecodeBytes);
end;

procedure TestTCipher_Blowfish.TestEncode;
begin
{ TODO :
Die Verschlüsselungs und Entschlüsselungstests müssen
für alle Blockmodi separat umgesetzt werden }
  DoTestEncode(FCipher_Blowfish.EncodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_Blowfish.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Blowfish.ClassByName('TCipher_Blowfish');
  CheckEquals(TCipher_Blowfish, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Twofish.Done;
begin
  FCipher_Twofish.Done;
end;

procedure TestTCipher_Twofish.Init(TestData: TCipherTestData);
var
  InitVector : RawByteString;
begin
  InitVector := TestData.InitVector;

  LimitKeyLength(TestData.Key, FCipher_Twofish.Context.KeySize);

  FCipher_Twofish.Mode := TestData.Mode;
  FCipher_Twofish.Init(BytesOf(TestData.Key),
                       BytesOf(InitVector),
                       TestData.Filler);
end;

procedure TestTCipher_Twofish.SetUp;
begin
  FCipher_Twofish := TCipher_Twofish.Create;
  // Testdaten initialisieren!
end;

procedure TestTCipher_Twofish.TearDown;
begin
  FCipher_Twofish.Free;
  FCipher_Twofish := nil;
end;

procedure TestTCipher_Twofish.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Twofish.Context;

  CheckEquals(  32,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals(4256,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Twofish.TestDecode;
begin
  DoTestDecode(FCipher_Twofish.DecodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_Twofish.TestEncode;
begin
  DoTestEncode(FCipher_Twofish.EncodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_Twofish.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Twofish.ClassByName('TCipher_Twofish');
  CheckEquals(TCipher_Twofish, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_IDEA.Done;
begin
  FCipher_IDEA.Done;
end;

procedure TestTCipher_IDEA.Init(TestData: TCipherTestData);
begin
  LimitKeyLength(TestData.Key, FCipher_IDEA.Context.KeySize);

  FCipher_IDEA.Mode := TestData.Mode;
  FCipher_IDEA.Init(BytesOf(TestData.Key),
                    BytesOf(TestData.InitVector),
                    TestData.Filler);
end;

procedure TestTCipher_IDEA.SetUp;
begin
  FCipher_IDEA := TCipher_IDEA.Create;

  SetLength(FTestData, 1);

  FTestData[0].OutputData  := '8c65cad843e79993ed41ea48fd665094a2256dd7b1d09a233dd2e8ecc9457f7e';
  FTestData[0].InputData   := TFormat_ESCAPE.Decode('\x30\x44\xED\x6E\x45\xA4' +
                                                    '\x96\xF5\xF6\x35\xA2\xEB' +
                                                    '\x3D\x1A\x5D\xD6\xCB\x1D' +
                                                    '\x09\x82\x2D\xBD\xF5\x60' +
                                                    '\xC2\xB8\x58\xA1\x91\xF9'+
                                                    '\x81\xB1');

  FTestData[0].Key        := 'TCipher_IDEA';
  FTestData[0].InitVector := '';
  FTestData[0].Filler     := $FF;
  FTestData[0].Mode       := cmCTSx;
end;

procedure TestTCipher_IDEA.TearDown;
begin
  FCipher_IDEA.Free;
  FCipher_IDEA := nil;
end;

procedure TestTCipher_IDEA.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_IDEA.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 208,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_IDEA.TestDecode;
begin
  DoTestDecode(FCipher_IDEA.DecodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_IDEA.TestEncode;
begin
  DoTestEncode(FCipher_IDEA.EncodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_IDEA.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_IDEA.ClassByName('TCipher_IDEA');
  CheckEquals(TCipher_IDEA, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Cast256.SetUp;
begin
  FCipher_Cast256 := TCipher_Cast256.Create;
end;

procedure TestTCipher_Cast256.TearDown;
begin
  FCipher_Cast256.Free;
  FCipher_Cast256 := nil;
end;

procedure TestTCipher_Cast256.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Cast256.Context;

  CheckEquals(  32,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 384,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Cast256.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Cast256.ClassByName('TCipher_Cast256');
  CheckEquals(TCipher_Cast256, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Mars.SetUp;
begin
  FCipher_Mars := TCipher_Mars.Create;
end;

procedure TestTCipher_Mars.TearDown;
begin
  FCipher_Mars.Free;
  FCipher_Mars := nil;
end;

procedure TestTCipher_Mars.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Mars.Context;

  CheckEquals(  56,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 160,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Mars.TestClassByName;
// ClassByName Tests für die restlichen Ciphers umsetzen!
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Mars.ClassByName('TCipher_Mars');
  CheckEquals(TCipher_Mars, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_RC4.SetUp;
begin
  FCipher_RC4 := TCipher_RC4.Create;
end;

procedure TestTCipher_RC4.TearDown;
begin
  FCipher_RC4.Free;
  FCipher_RC4 := nil;
end;

procedure TestTCipher_RC4.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_RC4.ClassByName('TCipher_RC4');
  CheckEquals(TCipher_RC4, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_RC4.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_RC4.Context;

  CheckEquals( 256,  ReturnValue.KeySize);
  CheckEquals(   1,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 258,  ReturnValue.UserSize);
  CheckEquals(true,  ReturnValue.UserSave);
  CheckEquals(true,  [ctStream, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_RC6.SetUp;
begin
  FCipher_RC6 := TCipher_RC6.Create;
end;

procedure TestTCipher_RC6.TearDown;
begin
  FCipher_RC6.Free;
  FCipher_RC6 := nil;
end;

procedure TestTCipher_RC6.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_RC6.ClassByName('TCipher_RC6');
  CheckEquals(TCipher_RC6, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_RC6.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_RC6.Context;

  CheckEquals( 256,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 272,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Square.SetUp;
begin
  FCipher_Square := TCipher_Square.Create;
end;

procedure TestTCipher_Square.TearDown;
begin
  FCipher_Square.Free;
  FCipher_Square := nil;
end;

procedure TestTCipher_Square.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Square.ClassByName('TCipher_Square');
  CheckEquals(TCipher_Square, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Square.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Square.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 288,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_SCOP.SetUp;
begin
  FCipher_SCOP := TCipher_SCOP.Create;
end;

procedure TestTCipher_SCOP.TearDown;
begin
  FCipher_SCOP.Free;
  FCipher_SCOP := nil;
end;

procedure TestTCipher_SCOP.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_SCOP.ClassByName('TCipher_SCOP');
  CheckEquals(TCipher_SCOP, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_SCOP.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_SCOP.Context;

  CheckEquals(  48,  ReturnValue.KeySize);
  CheckEquals(   4,  ReturnValue.BlockSize);
  CheckEquals(  32,  ReturnValue.BufferSize);
  CheckEquals(1548,  ReturnValue.UserSize);
  CheckEquals(true,  ReturnValue.UserSave);
  CheckEquals(true,  [ctStream, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Sapphire.SetUp;
begin
  FCipher_Sapphire := TCipher_Sapphire.Create;
end;

procedure TestTCipher_Sapphire.TearDown;
begin
  FCipher_Sapphire.Free;
  FCipher_Sapphire := nil;
end;

procedure TestTCipher_Sapphire.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Sapphire.ClassByName('TCipher_Sapphire');
  CheckEquals(TCipher_Sapphire, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Sapphire.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Sapphire.Context;

  CheckEquals(1024,  ReturnValue.KeySize);
  CheckEquals(   1,  ReturnValue.BlockSize);
  CheckEquals(  32,  ReturnValue.BufferSize);
  CheckEquals(1044,  ReturnValue.UserSize);
  CheckEquals(true,  ReturnValue.UserSave);
  CheckEquals(true,  [ctStream, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_1DES.Done;
begin
  FCipher_1DES.Done;
end;

procedure TestTCipher_1DES.Init(TestData: TCipherTestData);
begin
  LimitKeyLength(TestData.Key, FCipher_1DES.Context.KeySize);

  FCipher_1DES.Mode := TestData.Mode;
  FCipher_1DES.Init(BytesOf(TestData.Key),
                    BytesOf(TestData.InitVector),
                    TestData.Filler);
end;

procedure TestTCipher_1DES.SetUp;
begin
  FCipher_1DES := TCipher_1DES.Create;

  SetLength(FTestData, 1);

  FTestData[0].OutputData  := 'ad6942bbf668204d53cdc762139398c0300d850be2aa72096fdb5f8ed3e4cf8a';
  FTestData[0].InputData   := TFormat_ESCAPE.Decode('\x30\x44\xED\x6E\x45\xA4' +
                                                    '\x96\xF5\xF6\x35\xA2\xEB' +
                                                    '\x3D\x1A\x5D\xD6\xCB\x1D' +
                                                    '\x09\x82\x2D\xBD\xF5\x60' +
                                                    '\xC2\xB8\x58\xA1\x91\xF9' +
                                                    '\x81\xB1');

  FTestData[0].Key        := 'TCipher_1DES';
  FTestData[0].InitVector := '';
  FTestData[0].Filler     := $FF;
  FTestData[0].Mode       := cmCTSx;
end;

procedure TestTCipher_1DES.TearDown;
begin
  FCipher_1DES.Free;
  FCipher_1DES := nil;
end;

procedure TestTCipher_1DES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_1DES.ClassByName('TCipher_1DES');
  CheckEquals(TCipher_1DES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_1DES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_1DES.Context;

  CheckEquals(   8,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 256,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_1DES.TestDecode;
begin
  DoTestDecode(FCipher_1DES.DecodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_1DES.TestEncode;
begin
  DoTestEncode(FCipher_1DES.EncodeStringToBytes, self.Init, self.Done);
end;

procedure TestTCipher_2DES.SetUp;
begin
  FCipher_2DES := TCipher_2DES.Create;
end;

procedure TestTCipher_2DES.TearDown;
begin
  FCipher_2DES.Free;
  FCipher_2DES := nil;
end;

procedure TestTCipher_2DES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_2DES.ClassByName('TCipher_2DES');
  CheckEquals(TCipher_2DES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_2DES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_2DES.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 512,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_3DES.SetUp;
begin
  FCipher_3DES := TCipher_3DES.Create;
end;

procedure TestTCipher_3DES.TearDown;
begin
  FCipher_3DES.Free;
  FCipher_3DES := nil;
end;

procedure TestTCipher_3DES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_3DES.ClassByName('TCipher_3DES');
  CheckEquals(TCipher_3DES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_3DES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_3DES.Context;

  CheckEquals(  24,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 768,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_2DDES.SetUp;
begin
  FCipher_2DDES := TCipher_2DDES.Create;
end;

procedure TestTCipher_2DDES.TearDown;
begin
  FCipher_2DDES.Free;
  FCipher_2DDES := nil;
end;

procedure TestTCipher_2DDES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_2DDES.ClassByName('TCipher_2DDES');
  CheckEquals(TCipher_2DDES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_2DDES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_2DDES.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 512,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_3DDES.SetUp;
begin
  FCipher_3DDES := TCipher_3DDES.Create;
end;

procedure TestTCipher_3DDES.TearDown;
begin
  FCipher_3DDES.Free;
  FCipher_3DDES := nil;
end;

procedure TestTCipher_3DDES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_3DDES.ClassByName('TCipher_3DDES');
  CheckEquals(TCipher_3DDES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_3DDES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_3DDES.Context;

  CheckEquals(  24,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 768,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_3TDES.SetUp;
begin
  FCipher_3TDES := TCipher_3TDES.Create;
end;

procedure TestTCipher_3TDES.TearDown;
begin
  FCipher_3TDES.Free;
  FCipher_3TDES := nil;
end;

procedure TestTCipher_3TDES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_3TDES.ClassByName('TCipher_3TDES');
  CheckEquals(TCipher_3TDES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_3TDES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_3TDES.Context;

  CheckEquals(  24,  ReturnValue.KeySize);
  CheckEquals(  24,  ReturnValue.BlockSize);
  CheckEquals(  24,  ReturnValue.BufferSize);
  CheckEquals( 768,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_3Way.SetUp;
begin
  FCipher_3Way := TCipher_3Way.Create;
end;

procedure TestTCipher_3Way.TearDown;
begin
  FCipher_3Way.Free;
  FCipher_3Way := nil;
end;

procedure TestTCipher_3Way.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_3Way.ClassByName('TCipher_3Way');
  CheckEquals(TCipher_3Way, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_3Way.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_3Way.Context;

  CheckEquals(  12,  ReturnValue.KeySize);
  CheckEquals(  12,  ReturnValue.BlockSize);
  CheckEquals(  12,  ReturnValue.BufferSize);
  CheckEquals( 120,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Cast128.SetUp;
begin
  FCipher_Cast128 := TCipher_Cast128.Create;
end;

procedure TestTCipher_Cast128.TearDown;
begin
  FCipher_Cast128.Free;
  FCipher_Cast128 := nil;
end;

procedure TestTCipher_Cast128.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Cast128.ClassByName('TCipher_Cast128');
  CheckEquals(TCipher_Cast128, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Cast128.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Cast128.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 128,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Gost.SetUp;
begin
  FCipher_Gost := TCipher_Gost.Create;
end;

procedure TestTCipher_Gost.TearDown;
begin
  FCipher_Gost.Free;
  FCipher_Gost := nil;
end;

procedure TestTCipher_Gost.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Gost.ClassByName('TCipher_Gost');
  CheckEquals(TCipher_Gost, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Gost.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Gost.Context;

  CheckEquals(  32,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals(  32,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Misty.SetUp;
begin
  FCipher_Misty := TCipher_Misty.Create;
end;

procedure TestTCipher_Misty.TearDown;
begin
  FCipher_Misty.Free;
  FCipher_Misty := nil;
end;

procedure TestTCipher_Misty.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Misty.ClassByName('TCipher_Misty');
  CheckEquals(TCipher_Misty, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Misty.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Misty.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 128,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_NewDES.SetUp;
begin
  FCipher_NewDES := TCipher_NewDES.Create;
end;

procedure TestTCipher_NewDES.TearDown;
begin
  FCipher_NewDES.Free;
  FCipher_NewDES := nil;
end;

procedure TestTCipher_NewDES.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_NewDES.ClassByName('TCipher_NewDES');
  CheckEquals(TCipher_NewDES, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_NewDES.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_NewDES.Context;

  CheckEquals(  15,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 120,  ReturnValue.UserSize);
  CheckEquals(true,  ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Q128.SetUp;
begin
  FCipher_Q128 := TCipher_Q128.Create;
end;

procedure TestTCipher_Q128.TearDown;
begin
  FCipher_Q128.Free;
  FCipher_Q128 := nil;
end;

procedure TestTCipher_Q128.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Q128.ClassByName('TCipher_Q128');
  CheckEquals(TCipher_Q128, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Q128.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Q128.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 256,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_RC2.SetUp;
begin
  FCipher_RC2 := TCipher_RC2.Create;
end;

procedure TestTCipher_RC2.TearDown;
begin
  FCipher_RC2.Free;
  FCipher_RC2 := nil;
end;

procedure TestTCipher_RC2.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_RC2.ClassByName('TCipher_RC2');
  CheckEquals(TCipher_RC2, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_RC2.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_RC2.Context;

  CheckEquals( 128,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 128,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_RC5.SetUp;
begin
  FCipher_RC5 := TCipher_RC5.Create;
end;

procedure TestTCipher_RC5.TearDown;
begin
  FCipher_RC5.Free;
  FCipher_RC5 := nil;
end;

procedure TestTCipher_RC5.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_RC5.ClassByName('TCipher_RC5');
  CheckEquals(TCipher_RC5, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_RC5.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_RC5.Context;

  CheckEquals( 256,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 136,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_SAFER.SetUp;
begin
  FCipher_SAFER := TCipher_SAFER.Create;
end;

procedure TestTCipher_SAFER.TearDown;
begin
  FCipher_SAFER.Free;
  FCipher_SAFER := nil;
end;

procedure TestTCipher_SAFER.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_SAFER.ClassByName('TCipher_SAFER');
  CheckEquals(TCipher_SAFER, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_SAFER.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_SAFER.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 768,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Shark.SetUp;
begin
  FCipher_Shark := TCipher_Shark.Create;
end;

procedure TestTCipher_Shark.TearDown;
begin
  FCipher_Shark.Free;
  FCipher_Shark := nil;
end;

procedure TestTCipher_Shark.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Shark.ClassByName('TCipher_Shark');
  CheckEquals(TCipher_Shark, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Shark.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Shark.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals( 112,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_Skipjack.SetUp;
begin
  FCipher_Skipjack := TCipher_Skipjack.Create;
end;

procedure TestTCipher_Skipjack.TearDown;
begin
  FCipher_Skipjack.Free;
  FCipher_Skipjack := nil;
end;

procedure TestTCipher_Skipjack.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_Skipjack.ClassByName('TCipher_Skipjack');
  CheckEquals(TCipher_Skipjack, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_Skipjack.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Skipjack.Context;

  CheckEquals(  10,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals(2560,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_TEA.SetUp;
begin
  FCipher_TEA := TCipher_TEA.Create;
end;

procedure TestTCipher_TEA.TearDown;
begin
  FCipher_TEA.Free;
  FCipher_TEA := nil;
end;

procedure TestTCipher_TEA.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_TEA.ClassByName('TCipher_TEA');
  CheckEquals(TCipher_TEA, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_TEA.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_TEA.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals(  32,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

procedure TestTCipher_XTEA.SetUp;
begin
  FCipher_XTEA := TCipher_XTEA.Create;
end;

procedure TestTCipher_XTEA.TearDown;
begin
  FCipher_XTEA.Free;
  FCipher_XTEA := nil;
end;

procedure TestTCipher_XTEA.TestClassByName;
var
  ReturnValue : TDECCipherClass;
begin
  ReturnValue := FCipher_XTEA.ClassByName('TCipher_XTEA');
  CheckEquals(TCipher_XTEA, ReturnValue, 'Class is not registered');
end;

procedure TestTCipher_XTEA.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_XTEA.Context;

  CheckEquals(  16,  ReturnValue.KeySize);
  CheckEquals(   8,  ReturnValue.BlockSize);
  CheckEquals(   8,  ReturnValue.BufferSize);
  CheckEquals(  32,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
  CheckEquals(true,  [ctBlock, ctSymmetric] = ReturnValue.CipherType);
end;

{ TCipherBasis }

function TCipherBasis.ConvertHexVectorToBytes(Vector: string): TBytes;
var
  sl: TStringList;
  i : Integer;
  s : string;
begin
  System.Assert(Length(Vector) mod 4 = 0, 'Char count of ' + Vector + ' is not integral');

  SetLength(Result, Vector.Length div 4);

  if (Vector <> '') then
  begin
    sl := TStringList.Create;
    try
      sl.Delimiter := '\';
      sl.DelimitedText := StringReplace(Vector, 'x', '', [rfReplaceAll]);

      // first element is always empty
      sl.Delete(0);
      s := '';
      for i := 0 to sl.Count - 1 do
      begin
        sl[i] := '0x' + sl[i];
        Result[i] := StrToInt(sl[i]);
      end;
    finally
      sl.Free;
    end;
  end;
end;

procedure TCipherBasis.DoTestDecode(DecodeFunct: TEncodeDecodeFunc; InitProc: TInitProc; DoneProc: TDoneProc);
var
  Data          : TCipherTestData;
  Result        : TBytes;
  TempResultHex : RawByteString;
begin
{ TODO :
Das Problem ist hier: dass wir zu low level testen, da die bisherigen Textvektoren
ja immer von einem bestimmten CipherModus ausgehen, und nicht die
einzelnen DoEncode/DoDecode primitive. Diese sind später zu testen, wenn
wir die bisherigen Vektoren testen können. Dann können wir die nötigen
Daten synthetisieren. }
  for Data in FTestData do
  begin
    InitProc(Data);
    Result := DecodeFunct(RawByteString(Data.OutputData), TFormat_HEXL);
    DoneProc;

    TempResultHex := RawByteString(StringOf(Result));

    CheckEquals(Data.InputData, TempResultHex);
  end;
end;

procedure TCipherBasis.DoTestEncode(EncodeFunct: TEncodeDecodeFunc; InitProc: TInitProc; DoneProc: TDoneProc);
var
  Data          : TCipherTestData;
  Result        : TBytes;
  TempResultHex : RawByteString;
begin
{ TODO :
Das Problem ist hier: dass wir zu low level testen, da die bisherigen Textvektoren
ja immer von einem bestimmten CipherModus ausgehen, und nicht die
einzelnen DoEncode/DoDecode primitive. Diese sind später zu testen, wenn
wir die bisherigen Vektoren testen können. Dann können wir die nötigen
Daten synthetisieren. }
  for Data in FTestData do
  begin
    InitProc(Data);
    Result := EncodeFunct(RawByteString(Data.InputData), TFormat_COPY);
    DoneProc;

    TempResultHex := TFormat_HEXL.Encode(Result[0], length(Result));

    CheckEquals(Data.OutputData, TempResultHex);
  end;
end;

procedure TCipherBasis.LimitKeyLength(var Key: RawByteString; KeySize: Integer);
begin
  if Length(Key) > KeySize then
    Delete(Key, KeySize + 1, length(Key));
end;

{ TestTDECCipher }

procedure TestTDECCipher.SetUp;
begin
  inherited;
end;

procedure TestTDECCipher.TearDown;
begin
  inherited;
end;

procedure TestTDECCipher.TestIsClassListCreated;
begin
  CheckEquals(true, assigned(TDECCipher.ClassList), 'Class list has not been created in initialization');
end;

initialization
  // Register all test classes
  {$IFNDEF DUnitX}
  RegisterTests('DECCipher', [TestTDECCipher.Suite,
                              TestTCipher_Null.Suite,
                              TestTCipher_Blowfish.Suite,
                              TestTCipher_Twofish.Suite,
                              TestTCipher_IDEA.Suite,
                              TestTCipher_Cast256.Suite,
                              TestTCipher_Mars.Suite,
                              TestTCipher_RC4.Suite,
                              TestTCipher_RC6.Suite,
                              TestTCipher_Square.Suite,
                              TestTCipher_SCOP.Suite,
                              TestTCipher_Sapphire.Suite,
                              TestTCipher_1DES.Suite,
                              TestTCipher_2DES.Suite,
                              TestTCipher_3DES.Suite,
                              TestTCipher_2DDES.Suite,
                              TestTCipher_3DDES.Suite,
                              TestTCipher_3TDES.Suite,
                              TestTCipher_3Way.Suite,
                              TestTCipher_Cast128.Suite,
                              TestTCipher_Gost.Suite,
                              TestTCipher_Misty.Suite,
                              TestTCipher_NewDES.Suite,
                              TestTCipher_Q128.Suite,
                              TestTCipher_RC2.Suite,
                              TestTCipher_RC5.Suite,
                              TestTCipher_SAFER.Suite,
                              TestTCipher_Shark.Suite,
                              TestTCipher_Skipjack.Suite,
                              TestTCipher_TEA.Suite,
                              TestTCipher_XTEA.Suite]);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestTDECCipher);
  TDUnitX.RegisterTestFixture(TestTCipher_Null);
  TDUnitX.RegisterTestFixture(TestTCipher_Blowfish);
  TDUnitX.RegisterTestFixture(TestTCipher_Twofish);
  TDUnitX.RegisterTestFixture(TestTCipher_IDEA);
  TDUnitX.RegisterTestFixture(TestTCipher_Cast256);
  TDUnitX.RegisterTestFixture(TestTCipher_Mars);
  TDUnitX.RegisterTestFixture(TestTCipher_RC4);
  TDUnitX.RegisterTestFixture(TestTCipher_RC6);
  TDUnitX.RegisterTestFixture(TestTCipher_Rijndael);
  TDUnitX.RegisterTestFixture(TestTCipher_Square);
  TDUnitX.RegisterTestFixture(TestTCipher_SCOP);
  TDUnitX.RegisterTestFixture(TestTCipher_Sapphire);
  TDUnitX.RegisterTestFixture(TestTCipher_1DES);
  TDUnitX.RegisterTestFixture(TestTCipher_2DES);
  TDUnitX.RegisterTestFixture(TestTCipher_3DES);
  TDUnitX.RegisterTestFixture(TestTCipher_2DDES);
  TDUnitX.RegisterTestFixture(TestTCipher_3DDES);;
  TDUnitX.RegisterTestFixture(TestTCipher_3TDES);;
  TDUnitX.RegisterTestFixture(TestTCipher_3Way);
  TDUnitX.RegisterTestFixture(TestTCipher_Cast128);
  TDUnitX.RegisterTestFixture(TestTCipher_Gost);
  TDUnitX.RegisterTestFixture(TestTCipher_Misty);
  TDUnitX.RegisterTestFixture(TestTCipher_NewDES);
  TDUnitX.RegisterTestFixture(TestTCipher_Q128);
  TDUnitX.RegisterTestFixture(TestTCipher_RC2);
  TDUnitX.RegisterTestFixture(TestTCipher_RC5);
  TDUnitX.RegisterTestFixture(TestTCipher_SAFER);
  TDUnitX.RegisterTestFixture(TestTCipher_Shark);
  TDUnitX.RegisterTestFixture(TestTCipher_Skipjack);
  TDUnitX.RegisterTestFixture(TestTCipher_TEA);
  TDUnitX.RegisterTestFixture(TestTCipher_XTEA);
  {$ENDIF}
end.

