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
  // Testmethoden für Klasse TDECCipher
//{ TODO :
//Später ausdesignen, da v.a. virtuelle Methoden enthalten,
//sind aber Vorlage für die anderen! }
//  TestTDECCipher = class(TTestCase)
//  strict private
//    FDECCipher: TDECCipher;
//  public
//    procedure SetUp; override;
//    procedure TearDown; override;
//  published
//    procedure TestContext;
//    procedure TestInit1;
//    procedure TestEncodeBytes;
//    procedure TestDecodeBytes;
//  end;

  // Testmethoden für Klasse TCipher_Null
  TestTCipher_Null = class(TTestCase)
  strict private
    FCipher_Null: TCipher_Null;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  end;

  // A function with these parameters has to be passed to DoTestEncode/Decode to
  // make that one generic
  TEncodeDecodeFunc = function (const Source: TBytes; Format: TDECFormatClass = nil): TBytes of Object;

  // All known testvectors use the same filler byte and the same cmCTSx mode
  TCipherTestData = record
    InputData  : RawByteString;
    OutputData : RawByteString;
  end;

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

    procedure DoTestEncode(EncodeFunct: TEncodeDecodeFunc);
    procedure DoTestDecode(DecodeFunct: TEncodeDecodeFunc);
  end;

  // Testmethoden für Klasse TCipher_Blowfish
  [TestFixture]
  TestTCipher_Blowfish = class(TCipherBasis)
  strict private
    FCipher_Blowfish: TCipher_Blowfish;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
    procedure TestEncode;
    procedure TestDecode;
  end;

  // Testmethoden für Klasse TCipher_Twofish
  [TestFixture]
  TestTCipher_Twofish = class(TTestCase)
  strict private
    FCipher_Twofish: TCipher_Twofish;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_IDEA
  [TestFixture]
  TestTCipher_IDEA = class(TTestCase)
  strict private
    FCipher_IDEA: TCipher_IDEA;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Cast256
  [TestFixture]
  TestTCipher_Cast256 = class(TTestCase)
  strict private
    FCipher_Cast256: TCipher_Cast256;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Mars
  [TestFixture]
  TestTCipher_Mars = class(TTestCase)
  strict private
    FCipher_Mars: TCipher_Mars;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_RC4
  [TestFixture]
  TestTCipher_RC4 = class(TTestCase)
  strict private
    FCipher_RC4: TCipher_RC4;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_RC6
  [TestFixture]
  TestTCipher_RC6 = class(TTestCase)
  strict private
    FCipher_RC6: TCipher_RC6;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Rijndael
  [TestFixture]
  TestTCipher_Rijndael = class(TTestCase)
  strict private
    FCipher_Rijndael: TCipher_Rijndael;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Square
  [TestFixture]
  TestTCipher_Square = class(TTestCase)
  strict private
    FCipher_Square: TCipher_Square;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_SCOP
  [TestFixture]
  TestTCipher_SCOP = class(TTestCase)
  strict private
    FCipher_SCOP: TCipher_SCOP;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Sapphire
  [TestFixture]
  TestTCipher_Sapphire = class(TTestCase)
  strict private
    FCipher_Sapphire: TCipher_Sapphire;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_1DES
  [TestFixture]
  TestTCipher_1DES = class(TTestCase)
  strict private
    FCipher_1DES: TCipher_1DES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_2DES
  [TestFixture]
  TestTCipher_2DES = class(TTestCase)
  strict private
    FCipher_2DES: TCipher_2DES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_3DES
  [TestFixture]
  TestTCipher_3DES = class(TTestCase)
  strict private
    FCipher_3DES: TCipher_3DES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_2DDES
  [TestFixture]
  TestTCipher_2DDES = class(TTestCase)
  strict private
    FCipher_2DDES: TCipher_2DDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_3DDES
  [TestFixture]
  TestTCipher_3DDES = class(TTestCase)
  strict private
    FCipher_3DDES: TCipher_3DDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_3TDES
  [TestFixture]
  TestTCipher_3TDES = class(TTestCase)
  strict private
    FCipher_3TDES: TCipher_3TDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_3Way
  [TestFixture]
  TestTCipher_3Way = class(TTestCase)
  strict private
    FCipher_3Way: TCipher_3Way;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Cast128
  [TestFixture]
  TestTCipher_Cast128 = class(TTestCase)
  strict private
    FCipher_Cast128: TCipher_Cast128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Gost
  [TestFixture]
  TestTCipher_Gost = class(TTestCase)
  strict private
    FCipher_Gost: TCipher_Gost;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Misty
  [TestFixture]
  TestTCipher_Misty = class(TTestCase)
  strict private
    FCipher_Misty: TCipher_Misty;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_NewDES
  [TestFixture]
  TestTCipher_NewDES = class(TTestCase)
  strict private
    FCipher_NewDES: TCipher_NewDES;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Q128
  [TestFixture]
  TestTCipher_Q128 = class(TTestCase)
  strict private
    FCipher_Q128: TCipher_Q128;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_RC2
  [TestFixture]
  TestTCipher_RC2 = class(TTestCase)
  strict private
    FCipher_RC2: TCipher_RC2;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_RC5
  [TestFixture]
  TestTCipher_RC5 = class(TTestCase)
  strict private
    FCipher_RC5: TCipher_RC5;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_SAFER
  [TestFixture]
  TestTCipher_SAFER = class(TTestCase)
  strict private
    FCipher_SAFER: TCipher_SAFER;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Shark
  [TestFixture]
  TestTCipher_Shark = class(TTestCase)
  strict private
    FCipher_Shark: TCipher_Shark;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_Skipjack
  [TestFixture]
  TestTCipher_Skipjack = class(TTestCase)
  strict private
    FCipher_Skipjack: TCipher_Skipjack;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_TEA
  [TestFixture]
  TestTCipher_TEA = class(TTestCase)
  strict private
    FCipher_TEA: TCipher_TEA;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

  // Testmethoden für Klasse TCipher_XTEA
  [TestFixture]
  TestTCipher_XTEA = class(TTestCase)
  strict private
    FCipher_XTEA: TCipher_XTEA;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestContext;
  end;

implementation

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

procedure TestTCipher_Blowfish.SetUp;
var
  Password: string;
begin
  FCipher_Blowfish      := TCipher_Blowfish.Create;
//  FCipher_Blowfish.Context.

  Password := 'TCipher_Blowfish';
  if Length(Password) > FCipher_Blowfish.Context.KeySize then
    Password := Password.Remove(FCipher_Blowfish.Context.KeySize, Password.Length);

  FCipher_Blowfish.Mode := cmCTSx;
  FCipher_Blowfish.Init(Password, '', $FF);

  SetLength(FTestData, 1);
  FTestData[0].InputData  := '\x30\x44\xED\x6E\x45\xA4\x96\xF5\xF6\x35\xA2\xEB' +
                             '\x3D\x1A\x5D\xD6\xCB\x1D\x09\x82\x2D\xBD\xF5\x60' +
                             '\xC2\xB8\x58\xA1\x91\xF9\x81\xB1';
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
//FCipher_Blowfish.EncodeString()

  DoTestEncode(FCipher_Blowfish.EncodeBytes);
end;

procedure TestTCipher_Twofish.SetUp;
begin
  FCipher_Twofish := TCipher_Twofish.Create;
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
end;

procedure TestTCipher_IDEA.SetUp;
begin
  FCipher_IDEA := TCipher_IDEA.Create;
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
end;

procedure TestTCipher_Rijndael.SetUp;
begin
  FCipher_Rijndael := TCipher_Rijndael.Create;
end;

procedure TestTCipher_Rijndael.TearDown;
begin
  FCipher_Rijndael.Free;
  FCipher_Rijndael := nil;
end;

procedure TestTCipher_Rijndael.TestContext;
var
  ReturnValue: TCipherContext;
begin
  ReturnValue := FCipher_Rijndael.Context;

  CheckEquals(  32,  ReturnValue.KeySize);
  CheckEquals(  16,  ReturnValue.BlockSize);
  CheckEquals(  16,  ReturnValue.BufferSize);
  CheckEquals( 480,  ReturnValue.UserSize);
  CheckEquals(false, ReturnValue.UserSave);
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
end;

procedure TestTCipher_1DES.SetUp;
begin
  FCipher_1DES := TCipher_1DES.Create;
end;

procedure TestTCipher_1DES.TearDown;
begin
  FCipher_1DES.Free;
  FCipher_1DES := nil;
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
        Result[i] := sl[i].ToInteger;
      end;
    finally
      sl.Free;
    end;
  end;
end;

procedure TCipherBasis.DoTestDecode(DecodeFunct: TEncodeDecodeFunc);
var
  Data   : TCipherTestData;
  Result : TBytes;
  Res, Exp: RawByteString;
begin
  for Data in FTestData do
  begin
    Result := DecodeFunct(BytesOf(Data.OutputData), TFormat_HEXL);

    Res := BytesToRawString(Result);
    Exp := BytesToRawString(ConvertHexVectorToBytes(string(Data.InputData)));

    CheckEquals(Exp,
                Res);
  end;
end;

procedure TCipherBasis.DoTestEncode(EncodeFunct: TEncodeDecodeFunc);
var
  Data   : TCipherTestData;
  Result : TBytes;
begin
{ TODO :
Das Problem ist hier: dass wir zu low level testen, da die bisherigen Textvektoren
ja immer von einem bestimmten CipherModus ausgehen, und nicht die
einzelnen DoEncode/DoDecode primitive. Diese sind später zu testen, wenn
wir die bisherigen Vektoren testen können. Dann können wir die nötigen
Daten synthetisieren. }
  for Data in FTestData do
  begin
//    Result := EncodeFunct(BytesOf(Data.OutputData), TFormat_HEXL);
    Result := EncodeFunct(BytesOf(Data.InputData), TFormat_HEXL);

//    CheckEquals(BytesToRawString(ConvertHexVectorToBytes(string(Data.InputData))),
//                BytesToRawString(Result));
    CheckEquals(BytesToRawString(ConvertHexVectorToBytes(string(Data.OutputData))),
                BytesToRawString(Result));

  end;
end;

initialization
  // Register all test classes
//  RegisterTest(TestTDECCipher.Suite);
  {$IFNDEF DUnitX}
  RegisterTests('DECCipher', [TestTCipher_Null.Suite,
                              TestTCipher_Blowfish.Suite,
                              TestTCipher_Twofish.Suite,
                              TestTCipher_IDEA.Suite,
                              TestTCipher_Cast256.Suite,
                              TestTCipher_Mars.Suite,
                              TestTCipher_RC4.Suite,
                              TestTCipher_RC6.Suite,
                              TestTCipher_Rijndael.Suite,
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

