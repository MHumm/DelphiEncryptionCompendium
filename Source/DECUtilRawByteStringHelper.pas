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
unit DECUtilRawByteStringHelper;

interface

  /// <summary>
  ///   System.pas does not contain a RawByteString compatible version of this
  ///   routine so we rolled out own, copying and adapting code from system.pas
  ///   for the NextGen compiler and using a solution from Remy Lebeau for the
  ///   Win32/Win64 compiler.
  /// </summary>
  /// <param name="str">
  ///   String to be processed
  /// </param>
  procedure UniqueString(str: RawByteString);

implementation

uses
  System.TypInfo;

{$IFNDEF NEXTGEN}
type
  /// <summary>
  ///   Generic helper class for providing support for UniqueString with nearly
  ///   every possible string data type. Courtesy of Remy Lebeau.
  /// </summary>
  TUniqueStringHelper = class
    /// <summary>
    ///   Overwrites the string's contents in a secure way and returns an empty string.
    /// </summary>
    /// <param name="Str">
    ///   String to be safely overwritten
    /// </param>
    class procedure UniqueString<T>(var Str: T);
  end;

class procedure TUniqueStringHelper.UniqueString<T>(var Str: T);
begin
  if PTypeInfo(TypeInfo(T))^.Kind = tkLString then
    System.UniqueString(PAnsiString(@Str)^);
end;
{$ENDIF}

// Methode aus system.pas die auf RawByteString umgestrickt werden muss für mobile
// für Win32 gibt's dort eine ASM Variante, die alternativ benutzt werden könnte

{$IFDEF NEXTGEN}
type
  // For System.pas internal use only.
  // Keep in sync with system.pas
  PStrRec = ^StrRec;
  StrRec = packed record
  {$IF defined(CPU64BITS)}
    _Padding: Integer; // Make 16 byte align for payload..
  {$ENDIF}
    codePage: Word;
    elemSize: Word;
    refCnt: Integer;
    length: Integer;
  end;

threadvar
  InOutRes: Integer;

procedure _Halt(ErrCode: Integer);
begin
//  ExitCode := Code;
//  _Halt0;
end;

procedure RunErrorAt(ErrCode: Integer; ErrorAtAddr: Pointer);
begin
  ErrorAddr := ErrorAtAddr;
  _Halt(ErrCode);
end;

procedure ErrorAt(ErrorCode: Byte; ErrorAddr: Pointer);

const
  reMap: array [TRunTimeError] of Byte = (
    0,   { reNone }
    203, { reOutOfMemory }
    204, { reInvalidPtr }
    200, { reDivByZero }
    201, { reRangeError }
{   210    Abstract error }
    215, { reIntOverflow }
    207, { reInvalidOp }
    200, { reZeroDivide }
    205, { reOverflow }
    206, { reUnderflow }
    219, { reInvalidCast }
    216, { reAccessViolation }
    218, { rePrivInstruction }
    217, { reControlBreak }
    202, { reStackOverflow }
    220, { reVarTypeCast }
    221, { reVarInvalidOp }
    222, { reVarDispatch }
    223, { reVarArrayCreate }
    224, { reVarNotArray }
    225, { reVarArrayBounds }
{   226    Thread init failure }
    227, { reAssertionFailed }
    0,   { reExternalException not used here; in SysUtils }
    228, { reIntfCastError }
    229, { reSafeCallError }
    235, { reMonitorNotLocked }
    236, { reNoMonitorSupport }
{$IFDEF PC_MAPPED_EXCEPTIONS}
{   230   Reserved by the compiler for unhandled exceptions }
{$ENDIF PC_MAPPED_EXCEPTIONS}
{$IF defined(PC_MAPPED_EXCEPTIONS) or defined(STACK_BASED_EXCEPTIONS)}
{   231   Too many nested exceptions }
{$ENDIF}
{$IF Defined(LINUX) or Defined(MACOS) or Defined(ANDROID)}
{   232   Fatal signal raised on a non-Delphi thread }
    233, { reQuit }
{$ENDIF LINUX or MACOS or ANDROID}
{$IFDEF POSIX}
    234,  { reCodesetConversion }
{$ENDIF POSIX}
    237, { rePlatformNotImplemented }
    238  { reObjectDisposed }
);

begin
  errorCode := errorCode and 127;
  if Assigned(ErrorProc) then
    ErrorProc(errorCode, ErrorAddr);
  if errorCode = 0 then
    errorCode := InOutRes
  else if errorCode <= Byte(High(TRuntimeError)) then
    errorCode := reMap[TRunTimeError(errorCode)];
  RunErrorAt(errorCode, ErrorAddr);
end;

procedure _IntOver;
begin
  ErrorAt(Byte(reIntOverflow), ReturnAddress);
end;

function _NewAnsiString(CharLength: Integer; CodePage: Word): Pointer;
var
  P: PStrRec;
begin
  Result := nil;
  if CharLength > 0 then
  begin
    // Alloc an extra null for strings with even length.  This has no actual
    // cost since the allocator will round up the request to an even size
    // anyway. All _WideStr allocations have even length, and need a double
    // null terminator.
{ TODO : Umbauen um weg von _IntOver zu kommen?! In EIntOverflow Exception aus SysUtils?}
    if CharLength >= MaxInt - SizeOf(StrRec) then _IntOver;
    GetMem(P, CharLength + SizeOf(StrRec) + 1 + ((CharLength + 1) and 1));
    Result := Pointer(PByte(P) + SizeOf(StrRec));
    P.length := CharLength;
    P.refcnt := 1;
    if CodePage = 0 then
//{$IFDEF NEXTGEN}
      CodePage := Word(CP_UTF8);
//{$ELSE  NEXTGEN}
//      CodePage := Word(DefaultSystemCodePage);
//{$ENDIF NEXTGEN}
    P.codePage := CodePage;
    P.elemSize := 1;
    PWideChar(Result)[CharLength div 2] := #0;  // length guaranteed >= 2
  end;
end;

function _LStrClr(var S): Pointer;
var
  P: PStrRec;
begin
  if Pointer(S) <> nil then
  begin
    P := Pointer(PByte(S) - SizeOf(StrRec));
    Pointer(S) := nil;
    if P.refCnt > 0 then
    begin
      if AtomicDecrement(P.refCnt) = 0 then
        FreeMem(P);
    end;
  end;
  Result := @S;
end;

function InternalUniqueStringA(var Str: RawByteString): Pointer;
var
  P: PStrRec;
begin
  Result := Pointer(Str);
  if Result <> nil then
  begin
    Result := Pointer(Str);
    P := Pointer(PByte(Str) - sizeof(StrRec));
    if P.refCnt <> 1 then
    begin
      Result := _NewAnsiString(P.length, P.codePage);
//      Move(_PAnsiChr(Str)^, _PAnsiChr(Result)^, P.length);
      Move(PByte(Str)^, PByte(Result)^, P.length);
      _LStrClr(Str);
      Pointer(Str) := Result;
    end;
  end;
end;
{$ENDIF}

procedure UniqueString(str: RawByteString);
begin
  {$IFNDEF NEXTGEN}
  TUniqueStringHelper.UniqueString<RawByteString>(str);
  {$ELSE}
  InternalUniqueStringA(str);
  {$ENDIF}
end;

end.
