{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2017 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
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

unit DECBaseClass;

interface

{$I DECOptions.inc}

uses
  SysUtils, Classes, Generics.Collections;

type
  TDECClass = class of TDECObject;

  /// <summary>
  ///   Parent class of all cryptography and hash implementations
  /// </summary>
  TDECObject = class(TPersistent)
  public
    /// <summary>
    ///   Overrideable but otherwise empty constructor (calls his parent
    ///   constructor or course)
    /// </summary>
    constructor Create; virtual;
    /// <summary>
    ///   This function creates a unique Signature for each class using the
    ///   following naming scheme:
    ///
    ///   'Z' repeated n times (to fill space of 256 chars) + DEC ClassName
    ///
    ///   The CRC32 of the generated Signature is used as our unique Identity
    ///
    ///   Important Note:
    ///   DEC 5.2 introduced a bug which breaks backward compatibility with
    ///   DEC 5.1 by using String instead of AnsiString. This leads to different
    ///   Identities when using Unicode capable Delphi Versions (Delphi 2009+).
    ///
    ///   To restore the *wrong* behavior of DEC 5.2 enable the DEC52_IDENTITY option
    ///   in the configuration file DECOptions.inc.
    ///
    ///   With this and all future versions we will keep backward compatibility.
    /// </summary>
    class function Identity: Int64;
    {$IFDEF X86ASM}
    /// <summary>
    ///   Override FreeInstance to fill allocated Object with zeros, that is
    ///   safer for any access to invalid Pointers of released Objects.
    /// </summary>
    procedure FreeInstance; override;
    {$ENDIF X86ASM}
    class function SelfTest: Boolean; virtual;

    class procedure Register;
  end;

  /// <summary>
  ///   callback used when searching for a DEC class in the list of registered
  ///   DEC classes
  /// </summary>
  /// <param name="UserData">
  ///   ???
  /// </param>
  /// <param name="ClassType">
  ///   Here the entry to be checked has to be passed in.
  /// </param>
  /// <returns>
  ///   True if the entry passed in ClassType is the one one was looking for.
  /// </returns>
  TDECEnumClassesCallback = function(UserData: Pointer; ClassType: TClass): Boolean;

/// <summary>
///   unregister DEC classes
/// </summary>
procedure UnregisterDECClasses(const Classes: array of TClass);

/// <summary>
///   returns corrected, short Classname of any registered DEC class
/// </summary>
function DECClassName(ClassType: TClass): string;

/// <summary>
///   find a registered DEC class by it's identity number
/// </summary>
function DECClassByIdentity(Identity: Int64; ClassType: TClass): TDECClass;

/// <summary>
///   find DEC class by it's name, can be e.g. TCipher_Blowfish or just Blowfish
/// </summary>
function DECClassByName(const Name: string; ClassType: TClass): TDECClass;

/// <summary>
///   fill a StringList with registered DEC classes
/// </summary>
procedure DECClasses(List: TStrings; Include: TClass = nil; Exclude: TClass = nil);

/// <summary>
///   enumerate registered DEC classes using a Callback
/// </summary>
function DECEnumClasses(Callback: TDECEnumClassesCallback; UserData: Pointer;
                        Include: TClass = nil; Exclude: TClass = nil): TDECClass;

var
  /// <summary>
  ///   default used for generating Class Identities
  /// </summary>
  IdentityBase: Int64 = $25844852;

  /// <summary>
  ///   Size in bytes used for buffering data read from or written to a stream
  /// </summary>
  StreamBufferSize: Integer = 8192;

  {$IFDEF NEXTGEN}
  EmptyStr: string = '';
  /// <summary>
  ///   Pointer to an empty string. For non Nextgen platforms declared in SysUtils
  ///   for backwards compatibility only. here declared for NextGen only and
  ///   should get replaced
  /// </summary>
  NullStr: PString = @EmptyStr;
  {$ENDIF}

  DECClassList : TDictionary<Int64, TDECClass>;

implementation

uses
  DECUtil, DECCRC;

resourcestring
  sClassNotRegistered = 'Class %s is not registered';
  sWrongIdentity      = 'Another class "%s" with the same identity as "%s" has already been registered';

var
  FClasses: TList = nil;

function GetShortClassName(const ClassName: string): string;
var
  i: Integer;
begin
  Result := ClassName;
  i := Pos('_', Result);
  if i > 0 then
    Delete(Result, 1, i);
end;

procedure UnregisterDECClasses(const Classes: array of TClass);
var
  i, j: Integer;
begin
  if FClasses <> nil then
  begin
    for i := Low(Classes) to High(Classes) do
    begin
      j := FClasses.IndexOf(Classes[i]);
      if j >= 0 then
        FClasses.Delete(j);
    end;
  end;
end;

function DECClassName(ClassType: TClass): string;
begin
  if ClassType = nil then
    Result := ''
  else
    Result := GetShortClassName(ClassType.ClassName);
end;

// forward declaration of DEC enumeration callbacks
function DoFindIdentity(const Identity: Int64; ClassType: TDECClass): Boolean; forward;
function DoFindNameShort(const Name: string; const ClassType: TClass): Boolean; forward;
function DoFindNameLong(const Name: string; const ClassType: TClass): Boolean; forward;
function DoAddClass(List: TStrings; ClassType: TClass): Boolean; forward;

function DECClassByIdentity(Identity: Int64; ClassType: TClass): TDECClass;
begin
  Result := DECEnumClasses(@DoFindIdentity, @Identity, ClassType);
  if Result = nil then
    raise EDECClassNotRegisteredException.CreateResFmt(@sClassNotRegistered, [IntToHEX(Identity, 8)]);
end;

function DECClassByName(const Name: string; ClassType: TClass): TDECClass;
begin
  Result := nil;

  if Length(Name) > 0 then
  begin
    if GetShortClassName(Name) = Name then
      Result := DECEnumClasses(@DoFindNameShort, Pointer(Name), ClassType)
    else
      Result := DECEnumClasses(@DoFindNameLong, Pointer(Name), ClassType);
  end;

  if Result = nil then
    raise EDECClassNotRegisteredException.CreateResFmt(@sClassNotRegistered, [Name]);
end;

procedure DECClasses(List: TStrings; Include: TClass = nil; Exclude: TClass = nil);
begin
  if List <> nil then
  try
    List.BeginUpdate;
    List.Clear;
    DECEnumClasses(@DoAddClass, List, Include, Exclude);
  finally
    List.EndUpdate;
  end;
end;

function DECEnumClasses(Callback: TDECEnumClassesCallback; UserData: Pointer;
  Include: TClass = nil; Exclude: TClass = nil): TDECClass;
var
  i: Integer;
begin
  Result := nil;
  if (FClasses <> nil) and Assigned(Callback) then
  begin
    for i := 0 to FClasses.Count - 1 do
    begin
      if ((Include = nil) or     TClass(FClasses[i]).InheritsFrom(Include)) and
         ((Exclude = nil) or not TClass(FClasses[i]).InheritsFrom(Exclude)) and
         Callback(UserData, FClasses[i]) then
      begin
        Result := FClasses[i];
        Break;
      end;
    end;
  end;
end;

{
  Important Note about the following CallBacks (DoAddClass, DoFindIdentity,
  DoFindNameShort and DoFindNameLong):

  The CallBacks must be placed *outside* the calling function in order to
  be compatible with x64 compilers.
}

function DoAddClass(List: TStrings; ClassType: TClass): Boolean;
begin
  Result := False;
  List.AddObject(ClassType.ClassName, Pointer(ClassType));
end;

function DoFindIdentity(const Identity: Int64; ClassType: TDECClass): Boolean;
begin
  Result := ClassType.Identity = Identity;
end;

function DoFindNameShort(const Name: string; const ClassType: TClass): Boolean;
begin
  Result := CompareText(DECClassName(ClassType), Name) = 0;
end;

function DoFindNameLong(const Name: string; const ClassType: TClass): Boolean;
var
  s: string;
begin
  s := Name;
  Result := CompareText(ClassType.ClassName, Name) = 0;
end;

constructor TDECObject.Create;
begin
  inherited Create;
end;

class function TDECObject.Identity: Int64;
var
  Signature: {$IFDEF DEC52_IDENTITY}string{$ELSE !DEC52_IDENTITY}RawByteString{$ENDIF !DEC52_IDENTITY};
begin
  {$IFDEF DEC52_IDENTITY}
  Signature := StringOfChar(#$5A, 256 - Length(ClassName)) + UpperCase(ClassName);
  Result := CRC32(IdentityBase, Signature[Low(Signature)],
                                Length(Signature) * SizeOf(Signature[Low(Signature)]));
  {$ELSE !DEC52_IDENTITY}
  Signature := RawByteString(StringOfChar(#$5A, 256 - Length(ClassName)) + UpperCase(ClassName));
  Result := CRC32(IdentityBase, Signature[Low(Signature)], Length(Signature));
  {$ENDIF !DEC52_IDENTITY}
end;

class procedure TDECObject.Register;
begin
  DECClassList.Add(Identity, self);
end;

{$IFDEF X86ASM}
procedure TDECObject.FreeInstance;
// Override FreeInstance to fill allocated Object with zeros, that is
// safer for any access to invalid Pointers of released Objects
asm
      PUSH    EBX
      PUSH    EDI
      MOV     EBX,EAX
      CALL    TObject.CleanupInstance
      MOV     EAX,[EBX]
      CALL    TObject.InstanceSize
      MOV     ECX,EAX
      MOV     EDI,EBX
      XOR     EAX,EAX
      REP     STOSB
      MOV     EAX,EBX
      CALL    System.@FreeMem
      POP     EDI
      POP     EBX
end;
{$ENDIF X86ASM}

class function TDECObject.SelfTest: Boolean;
begin
  {$IFDEF FPC}
  Result := False; // suppress FPC compiler warning
  {$ENDIF FPC}
  // C++ does not support virtual static functions thus the base cannot be
  // marked 'abstract'. This is our workaround:
  raise EDECAbstractError.Create(Self);
end;

{$IFDEF DELPHIORBCB}
procedure ModuleUnload(Instance: NativeInt);
var // automaticaly deregistration/releasing
  i: Integer;
begin
  if FClasses <> nil then
  begin
    for i := FClasses.Count - 1 downto 0 do
    begin
      if Integer(FindClassHInstance(TClass(FClasses[i]))) = Instance then
        FClasses.Delete(i);
    end;
  end;
end;
{$ENDIF DELPHIORBCB}

initialization
  {$IFDEF DELPHIORBCB}
  AddModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}
  FClasses := TList.Create;

  DECClassList := TDictionary<Int64, TDECClass>.Create;

finalization
  {$IFDEF DELPHIORBCB}
  RemoveModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}
  FClasses.Free;

  DECClassList.Free;
end.
