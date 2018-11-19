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

unit DECBaseClass;

interface

{$I DECOptions.inc}

uses
  SysUtils, Classes, Generics.Collections;

type
  /// <summary>
  ///   Class type for the base class from which all other DEC classes inherit
  ///   in order to be able to create lists of classes, pick an entry of such a
  ///   list and construct an object out of it
  /// </summary>
  TDECClass = class of TDECObject;

  /// <summary>
  ///   Generic list of DEC classes with the identity as key
  /// </summary>
  TDECClassList = class(TDictionary<Int64, TDECClass>)
  strict private
    /// <summary>
    ///   Returns short Classname of any DEC derrived class. This is the part
    ///   of the class name after the _ so for THash_RipeMD160 it will be RipeMD160.
    /// </summary>
    /// <param name="ClassName">
    ///   Complete class name
    /// </param>
    /// <returns>
    ///   Short class name
    /// </returns>
    class function GetShortClassNameInternal(const ClassName: string): string;

    /// <summary>
    ///   Checks whether a given class type has a given DEC Identity
    /// </summary>
    /// <param name="Identity">
    ///   DEC identity to check
    /// </param>
    /// <param name="ClassType">
    ///   Class type which should be checked if it is for the given DEC identity
    /// </param>
    /// <returns>
    ///   true if the class type represents the given identity
    /// </returns>
    function HasIdentity(const Identity: Int64; ClassType: TDECClass): Boolean;

    /// <summary>
    ///   Checks if a given class type has the same short class name as given
    /// </summary>
    /// <param name="Name">
    ///   Short class name, e.g. HEXL
    /// </param>
    /// <param name="ClassType">
    ///   Class reference to check against
    /// </param>
    /// <returns>
    ///   true if the class reference is for the given short name
    /// </returns>
    function DoFindNameShort(const Name: string; const ClassType: TClass): Boolean;
    /// <summary>
    ///   Checks if a given class type has the same long class name as given
    /// </summary>
    /// <param name="Name">
    ///   Long class name, e.g. TFormat_HEXL
    /// </param>
    /// <param name="ClassType">
    ///   Class reference to check against
    /// </param>
    /// <returns>
    ///   true if the class reference is for the given long name
    /// </returns>
    function DoFindNameLong(const Name: string; const ClassType: TClass): Boolean;
  public
    /// <summary>
    ///   Tries to find a class type by its name
    /// </summary>
    /// <param name="Name">
    ///   Name to look for in the list
    /// </param>
    /// <returns>
    ///   Returns the class type if found. if it could not be found a
    ///   EDECClassNotRegisteredException will be thrown
    /// </returns>
    function ClassByName(const Name: string): TDECClass;

    /// <summary>
    ///   Tries to find a class type by its numeric identity DEC assigned to it.
    ///   Useful for file headers, so they can easily encode numerically which
    ///   cipher class was being used.
    /// </summary>
    /// <param name="Identity">
    ///   Identity to look for
    /// </param>
    function ClassByIdentity(Identity: Int64): TDECClass;
    /// <summary>
    ///   Returns a list of all classes registered in this list
    /// </summary>
    /// <param name="List">
    ///   List where the registered classes shall be added to. The string is the
    ///   long class name, the object the class reference. The list is being
    ///   cleared first and when an uncreated list is given nothing is being done
    /// </param>
    procedure GetClassList(List: TStrings);
    /// <summary>
    ///   Returns short Classname of any DEC derrived class. This is the part
    ///   of the class name after the _ so for THash_RipeMD160 it will be RipeMD160.
    /// </summary>
    /// <param name="ClassType">
    ///   Class type for the class where the name shall be returned from
    /// </param>
    /// <returns>
    ///   Short class name or empty string if ClassType is nil.
    /// </returns>
    class function GetShortClassName(ClassType: TClass): string;
  end;

  /// <summary>
  ///   Parent class of all cryptography and hash implementations
  /// </summary>
  TDECObject = class(TPersistent)
  strict protected
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

    /// <summary>
    ///   Registers this class type in the list of DEC classes (ClassList).
    ///   Trying to register an already registered class will raise an exception.
    /// </summary>
    /// <param name="ClassList">
    ///   List to which the own class type shall be added. This allows subclasses
    ///   to have their own lists
    /// </param>
    class procedure RegisterClass(ClassList : TDECClassList);
    /// <summary>
    ///   Removes tthis class type from the list of registered DEC classes
    ///   (ClassList). Trying to unregister a non registered class is a do nothing
    ///   operation.
    /// </summary>
    /// <param name="ClassList">
    ///   List from which the own class type shall be removed. This allows
    ///   subclasses to have their own lists
    /// </param>
    class procedure UnregisterClass(ClassList : TDECClassList);
  end;

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

{
  Important Note about the following CallBacks (DoAddClass, DoFindIdentity,
  DoFindNameShort and DoFindNameLong):

  The CallBacks must be placed *outside* the calling function in order to
  be compatible with x64 compilers.
}

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

class procedure TDECObject.RegisterClass(ClassList : TDECClassList);
begin
  ClassList.Add(Identity, self);
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

class procedure TDECObject.UnregisterClass(ClassList : TDECClassList);
begin
  ClassList.Remove(Identity);
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

{ TDECClassList }

function TDECClassList.DoFindNameShort(const Name: string; const ClassType: TClass): Boolean;
begin
  Result := CompareText(TDECClassList.GetShortClassName(ClassType), Name) = 0;
end;

function TDECClassList.DoFindNameLong(const Name: string; const ClassType: TClass): Boolean;
var
  s: string;
begin
  s := Name;
  Result := CompareText(ClassType.ClassName, Name) = 0;
end;

function TDECClassList.ClassByIdentity(Identity: Int64): TDECClass;
var
  i: Integer;
begin
  Result := nil;
  for i := 0 to self.Count - 1 do
  begin
    if HasIdentity(Identity, Items[i]) then
    begin
      Result := Items[i];
      Break;
    end;
  end;

  if Result = nil then
    raise EDECClassNotRegisteredException.CreateResFmt(@sClassNotRegistered, [IntToHEX(Identity, 8)]);
end;

function TDECClassList.ClassByName(const Name: string): TDECClass;
var
  FindNameShort : Boolean;
  Pair          : TPair<Int64, TDECCLass>;
begin
  Result := nil;

  if Length(Name) > 0 then
  begin
    FindNameShort := GetShortClassNameInternal(Name) = Name;

    for Pair in self do
    begin
      if FindNameShort then
      begin
        if DoFindNameShort(Name, Pair.Value) then
        begin
          result := Pair.Value;
          break;
        end;
      end
      else
        if DoFindNameLong(Name, Pair.Value) then
        begin
          result := Pair.Value;
          break;
        end;
    end;
  end;

  if Result = nil then
    raise EDECClassNotRegisteredException.CreateResFmt(@sClassNotRegistered, [Name]);
end;

procedure TDECClassList.GetClassList(List: TStrings);
var
  Pair : TPair<Int64, TDECCLass>;
begin
  if List <> nil then
  try
    List.BeginUpdate;
    List.Clear;

    for Pair in self do
      List.AddObject(Pair.Value.ClassName, TObject(Pair.Value));

  finally
    List.EndUpdate;
  end;
end;

class function TDECClassList.GetShortClassName(ClassType: TClass): string;
begin
  if ClassType = nil then
    Result := ''
  else
    Result := GetShortClassNameInternal(ClassType.ClassName);
end;

class function TDECClassList.GetShortClassNameInternal(const ClassName: string): string;
var
  i: Integer;
begin
  Result := ClassName;
  i := Pos('_', Result);
  if i > 0 then
    Delete(Result, 1, i);
end;

function TDECClassList.HasIdentity(const Identity: Int64;
  ClassType: TDECClass): Boolean;
begin
  Result := ClassType.Identity = Identity;
end;

initialization
  {$IFDEF DELPHIORBCB}
  AddModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}
  FClasses := TList.Create;

finalization
  {$IFDEF DELPHIORBCB}
  RemoveModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}
  FClasses.Free;
end.
