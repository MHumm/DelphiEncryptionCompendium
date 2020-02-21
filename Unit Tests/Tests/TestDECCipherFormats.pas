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

  Classes, DECBaseClass, SysUtils, Generics.Collections;

type
  // Test methods for class TDECClassList
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECCipherFormats = class(TTestCase)
  strict private

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
  DECFormat, DECCiphers;

procedure TestTDECCipherFormats.TestDecodeRawByteStringToBytes;
begin

end;

procedure TestTDECCipherFormats.TestDecodeStringToBytes;
begin

end;

procedure TestTDECCipherFormats.SetUp;
begin
//
end;

procedure TestTDECCipherFormats.TearDown;
begin
//
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
begin

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
