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
unit TestDECBaseClass;

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
  TestTDECClassList = class(TTestCase)
  strict private
    FDECClassList: TDECClassList;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestClassByName;
    procedure TestClassByIdentity;
    procedure TestGetClassList;
  end;

  // Test methods for class TDECObject
  {$IFDEF DUnitX} [TestFixture] {$ENDIF}
  TestTDECObject = class(TTestCase)
  strict private
    FDECObject: TDECObject;
  public
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestIdentity;
    procedure TestRegisterClass;
    procedure TestUnregisterClass;
    procedure TestGetShortClassNameFromName;
    procedure TestGetShortClassNameFromName2;
    procedure TestGetShortClassName;
    procedure TestGetShortClassName2;
  end;

implementation

uses
  DECFormat, DECCiphers;

procedure TestTDECClassList.SetUp;
begin
  FDECClassList := TDECClassList.Create;

  FDECClassList.Add(TFormat_HEX.Identity, TFormat_HEX);
  FDECClassList.Add(TFormat_HEXL.Identity, TFormat_HEXL);
  FDECClassList.Add(TFormat_DECMIME32.Identity, TFormat_DECMIME32);
  FDECClassList.Add(TFormat_Base64.Identity, TFormat_Base64);
  FDECClassList.Add(TFormat_UU.Identity, TFormat_UU);
  FDECClassList.Add(TFormat_XX.Identity, TFormat_XX);
  FDECClassList.Add(TFormat_ESCAPE.Identity, TFormat_ESCAPE);
end;

procedure TestTDECClassList.TearDown;
begin
  FDECClassList.Free;
  FDECClassList := nil;
end;

procedure TestTDECClassList.TestClassByIdentity;
var
  ReturnValue: TDECClass;
begin
  ReturnValue := FDECClassList.ClassByIdentity(TFormat_HEX.Identity);
  CheckEquals(ReturnValue, TFormat_HEX);
  CheckNotEquals(ReturnValue = TFormat_HEXL, true);

  ReturnValue := FDECClassList.ClassByIdentity(TFormat_Base64.Identity);
  CheckEquals(ReturnValue, TFormat_Base64);

  ReturnValue := FDECClassList.ClassByIdentity(TFormat_ESCAPE.Identity);
  CheckEquals(ReturnValue, TFormat_ESCAPE);
end;

procedure TestTDECClassList.TestClassByName;
var
  ReturnValue: TDECClass;
begin
  ReturnValue := FDECClassList.ClassByName('TFormat_HEX');
  CheckEquals(ReturnValue, TFormat_HEX);

  ReturnValue := FDECClassList.ClassByName('TFormat_hex');
  CheckEquals(ReturnValue, TFormat_HEX);

  ReturnValue := FDECClassList.ClassByName('TFormat_HEXL');
  CheckEquals(ReturnValue, TFormat_HEXL);

  ReturnValue := FDECClassList.ClassByName('TFormat_ESCAPE');
  CheckEquals(ReturnValue, TFormat_ESCAPE);
end;

procedure TestTDECClassList.TestGetClassList;
var
  sl : TStringList;
begin
  sl := TStringList.Create;
  try
    FDECClassList.GetClassList(sl);

    CheckEquals(sl.Count, 7, 'Wrong number of registered classes');
    CheckEquals(sl.IndexOf('TFormat_HEX')       >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_HEXL')      >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_DECMIME32') >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_Base64')    >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_UU')        >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_XX')        >= 0, true);
    CheckEquals(sl.IndexOf('TFormat_ESCAPE')    >= 0, true);
  finally
    sl.Free;
  end;
end;

procedure TestTDECObject.TestGetShortClassName;
begin
  CheckEquals(TFormat_HEXL.GetShortClassName,
              'HEXL');
end;

procedure TestTDECObject.TestGetShortClassName2;
begin
  CheckEquals(TCipher_Skipjack.GetShortClassName,
              'Skipjack');
end;

procedure TestTDECObject.TestGetShortClassNameFromName;
begin
  CheckEquals(TDECClass.GetShortClassNameFromName('TFormat_HEXL'),
              'HEXL');
end;

procedure TestTDECObject.TestGetShortClassNameFromName2;
begin
  CheckEquals(TDECClass.GetShortClassNameFromName('TCipher_Skipjack'),
              'Skipjack');
end;

procedure TestTDECObject.SetUp;
begin
  FDECObject := TDECObject.Create;
end;

procedure TestTDECObject.TearDown;
begin
  FDECObject.Free;
  FDECObject := nil;
end;

procedure TestTDECObject.TestIdentity;
var
  ReturnValue: Int64;
begin
  // We do test the normal identity format, not the "special" one from DEC V5.2
  ReturnValue := FDECObject.Identity;
  CheckEquals(3520275915, ReturnValue, 'Wrong Identity Value');

  ReturnValue := TFormat_Hex.Identity;
  CheckEquals(3786628779, ReturnValue, 'Wrong Identity Value');
end;

procedure TestTDECObject.TestRegisterClass;
var
  ClassList   : TDECClassList;
  ReturnValue : Boolean;
begin
  ClassList := TDECClassList.Create(4);
  try
    FDECObject.RegisterClass(ClassList);

    ReturnValue := ClassList.ContainsValue(TDECObject);
    CheckEquals(true, ReturnValue, 'Class TDECObject has not been registered in class list');

    CheckEquals(1, ClassList.Count, 'Invalid number of registered classes');

    TFormat_HEX.RegisterClass(ClassList);

    ReturnValue := ClassList.ContainsValue(TFormat_HEX);
    CheckEquals(true, ReturnValue, 'Class TFormat_HEX has not been registered in class list');

    ReturnValue := ClassList.ContainsValue(TDECObject);
    CheckEquals(true, ReturnValue, 'Class TDECObject has not been registered in class list');

    CheckEquals(2, ClassList.Count, 'Invalid number of registered classes');
  finally
    ClassList.Free;
  end;
end;

procedure TestTDECObject.TestUnregisterClass;
var
  ClassList   : TDECClassList;
  ReturnValue : Boolean;
begin
  ClassList := TDECClassList.Create(4);
  try
    FDECObject.RegisterClass(ClassList);
    TFormat_HEX.RegisterClass(ClassList);

    CheckEquals(2, ClassList.Count, 'Invalid number of registered classes');

    FDECObject.UnregisterClass(ClassList);

    ReturnValue := ClassList.ContainsValue(TFormat_HEX);
    CheckEquals(true, ReturnValue, 'Wrong class has ben deregistered from class list');

    CheckEquals(1, ClassList.Count, 'Invalid number of registered classes');
  finally
    ClassList.Free;
  end;
end;

initialization
  // Register any test cases with the test runner
  {$IFNDEF DUnitX}
  RegisterTests('DECBaseClass', [TestTDECClassList.Suite, TestTDECObject.Suite]);
  {$ELSE}
  TDUnitX.RegisterTestFixture(TestTDECClassList);
  TDUnitX.RegisterTestFixture(TestTDECObject);
  {$ENDIF}
end.

