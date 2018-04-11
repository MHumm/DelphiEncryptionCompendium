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

/// <summary>
///   Most simple demonstration of using a DEC cipher
/// </summary>
program Cipher_Console;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DECBaseClass in '..\..\Source\DECBaseClass.pas',
  DECCipherBase in '..\..\Source\DECCipherBase.pas',
  DECCipherModes in '..\..\Source\DECCipherModes.pas',
  DECCiphers in '..\..\Source\DECCiphers.pas',
  DECCRC in '..\..\Source\DECCRC.pas',
  DECFormat in '..\..\Source\DECFormat.pas',
  DECFormatBase in '..\..\Source\DECFormatBase.pas',
  DECTypes in '..\..\Source\DECTypes.pas',
  DECUtil in '..\..\Source\DECUtil.pas',
  DECData in '..\..\Source\DECData.pas',
  DECCipherFormats in '..\..\Source\DECCipherFormats.pas';

var
  Cipher     : TCipher_1DES;
  // We use raw byte string here since Unicode handling of Windows console
  // is not given
  SourceText : RawByteString;
  CipherText : string;
  // Key for the initialization of our encryption run
  CipherKey  : RawByteString;
  IV: RawByteString;
  Input, Output:TBytes;
  I : Integer;
begin
  Cipher := TCipher_1DES.Create;

  try
    // Init our encryption
    CipherKey := 'Passwort';
    IV := #0#0#0#0#0#0#0#0;
    Cipher.Init(CipherKey, IV, 0);
    Cipher.Mode := cmCBCx;

    SourceText := 'Beispielklartext';
    Input := System.SysUtils.BytesOf(SourceText);

    Output := Cipher.EncodeBytes(Input);
    for i := 0 to high(Output) do
      Write(IntToHex(Output[i], 2), ' ');

    // Encrypt some text

//    CipherText := DECUtil.BytesToRawString(Cipher.EncodeString(SourceText, TFormat_HEX));
//    WriteLn('Cipher of ' + SourceText + ' is: ' + CipherText);

//    // Show that decryption works
//    Cipher.Init(CipherKey);
//    WriteLn('Plain text of ' + CipherText + ' is: ' +
//      StringOf(Cipher.DecodeString(StringOf(TFormat_HEX.Decode(BytesOf(CipherText))), TFormat_Copy)));
//
//    // Show that using a different key results in a different output

    ReadLn;

    try
    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;
  finally
    Cipher.Free;
  end;
end.
