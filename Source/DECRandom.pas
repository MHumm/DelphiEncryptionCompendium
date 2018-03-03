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

{
  Secure Pseudo Random Number Generator based on Yarrow
}

unit DECRandom;

interface

{$I DECOptions.inc}

uses
  SysUtils, DECUtil, DECHashBase, DECHash;

function RandomSystemTime: Int64;
procedure RandomBuffer(var Buffer; Size: Integer);
function RandomBytes(Size: Integer): TBytes;
function RandomRawByteString(Size: Integer): RawByteString; deprecated; // please use RandomBytes now
function RandomLong: UInt32;
procedure RandomSeed(const Buffer; Size: Integer); overload;
procedure RandomSeed; overload;

var
  // secure PRNG initialized by this unit
  DoRandomBuffer: procedure(var Buffer; Size: Integer); register = nil;
  DoRandomSeed: procedure(const Buffer; Size: Integer); register = nil;
  RandomClass: TDECHashClass = THash_SHA256;

implementation

uses
  {$IFDEF DELPHI_2010_UP}
    Diagnostics
  {$ELSE !DELPHI_2010_UP}
    {$IFDEF MSWINDOWS}
    Windows
    {$ELSE !MSWINDOWS}
      {$IFDEF FPC}
      LclIntf
      {$ENDIF !FPC}
    {$ENDIF !MSWINDOWS}
  {$ENDIF !DELPHI_2010_UP}
  ;

{$IFOPT Q+}{$DEFINE RESTORE_OVERFLOWCHECKS}{$Q-}{$ENDIF}
{$IFOPT R+}{$DEFINE RESTORE_RANGECHECKS}{$R-}{$ENDIF}

var
  FRegister: array[0..127] of Byte;
  FCounter: Cardinal;
  FHash: TDECHash = nil;
  FRndSeed: Cardinal = 0;

function RandomSystemTime: Int64;
// create Seed from Systemtime and PerformanceCounter
type
  TInt64Rec = packed record
    Lo, Hi: UInt32;
  end;
var
  {$IF defined(MSWINDOWS) and not defined(DELPHI_2010_UP)}
  SysTime: TSystemTime;
  {$ELSE}
  Hour, Minute, Second, Milliseconds: Word;
  {$ENDIF}
  Counter: TInt64Rec;
  Time: Cardinal;
begin
  {$IF defined(MSWINDOWS) and not defined(DELPHI_2010_UP)}
  GetSystemTime(SysTime);
  Time := ((Cardinal(SysTime.wHour) * 60 + SysTime.wMinute) * 60 + SysTime.wSecond) * 1000 + SysTime.wMilliseconds;
  QueryPerformanceCounter(Int64(Counter));
  {$ELSE}
  DecodeTime(Now, Hour, Minute, Second, Milliseconds);
  Time := ((Cardinal(Hour) * 60 + Minute) * 60 + Second) * 1000 + Milliseconds;
    {$IFDEF DELPHI_2010_UP}
    Int64(Counter) := TStopWatch.GetTimeStamp; // uses System.Diagnostics
    {$ELSE}
      {$IFDEF FPC}
      Int64(Counter) := LclIntf.GetTickCount * 10000 {TicksPerMillisecond}; // uses LclIntf
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}

  Result := Time + Counter.Hi;
  Inc(Result, Ord(Result < Time)); // add "carry flag"
  Inc(Result, Counter.Lo);
end;

function DoRndBuffer(Seed: Cardinal; var Buffer; Size: Integer): Cardinal;
// comparable to Delphi Random() function
var
  P: PByte;
begin
  Result := Seed;
  P := @Buffer;
  if P <> nil then
  begin
    while Size > 0 do
    begin
      Result := Result * $08088405 + 1;
      P^ := Byte(Result shr 24);
      Inc(P);
      Dec(Size);
    end;
  end;
end;

procedure RandomBuffer(var Buffer; Size: Integer);
begin
  if Assigned(DoRandomBuffer) then
    DoRandomBuffer(Buffer, Size)
  else
    FRndSeed := DoRndBuffer(FRndSeed, Buffer, Size);
end;

function RandomBytes(Size: Integer): TBytes;
begin
  SetLength(Result, Size);
  RandomBuffer(Result[0], Size);
end;

function RandomRawByteString(Size: Integer): RawByteString;
begin
  SetLength(Result, Size);
  RandomBuffer(Result[Low(Result)], Size);
end;

function RandomLong: UInt32;
begin
  RandomBuffer(Result, SizeOf(Result));
end;

procedure RandomSeed(const Buffer; Size: Integer);
begin
  if Assigned(DoRandomSeed) then
    DoRandomSeed(Buffer, Size)
  else
  begin
    if Size >= 0 then
    begin
      FRndSeed := 0;
      while Size > 0 do
      begin
        Dec(Size);
        FRndSeed := (FRndSeed shl 8 + FRndSeed shr 24) xor TByteArray(Buffer)[Size]
      end;
    end
    else
      FRndSeed := RandomSystemTime;
  end;
end;

procedure RandomSeed;
begin
  RandomSeed('', -1);
end;

function DoProcess: Byte;
begin
  if FHash = nil then
    FHash := RandomClass.Create;

  FHash.Init;
  FHash.Calc(FCounter, SizeOf(FCounter));
{ TODO : Wenn in DECOptions.inc die Benutzung von ASM Code aktiviert ist, crasht
  das Programm mit Zugriffsverletzung  in der nächsten Zeile. Grund ist jedoch noch
  unbekannt.}
  FHash.Calc(FRegister, SizeOf(FRegister));
  FHash.Done;

{ TODO : Auskommentiert wegen Verlegung von Digest nach Protected in DECHash um
 von PByteArray weg zu kommen}
//  FRegister[FCounter mod SizeOf(FRegister)] := FRegister[FCounter mod SizeOf(FRegister)] xor FHash.Digest[0];
  FRegister[FCounter mod SizeOf(FRegister)] := FRegister[FCounter mod SizeOf(FRegister)] xor FHash.DigestAsBytes[0];
  Inc(FCounter);

//  Result := FHash.Digest[1]; // no real predictable dependency to above FHash.Digest[0] !
  Result := FHash.DigestAsBytes[1]; // no real predictable dependency to above FHash.Digest[0] !
end;

procedure DoBuffer(var Buffer; Size: Integer);
var
  i: Integer;
begin
  for i := 0 to Size - 1 do
    TByteArray(Buffer)[i] := DoProcess;
end;

procedure DoSeed(const Buffer; Size: Integer);
var
  i: Integer;
  t: Cardinal;
begin
  if Size >= 0 then
  begin
    // initalize a repeatable Seed
    FillChar(FRegister, SizeOf(FRegister), 0);
    FCounter := 0;
    for i := 0 to Size - 1 do
      FRegister[i mod SizeOf(FRegister)] := FRegister[i mod SizeOf(FRegister)] xor TByteArray(Buffer)[i];
  end
  else
  begin
    // ! ATTENTION !
    // Initalizes a non-repeatable Seed based on Timers, which is not secure
    // and inpredictable. The user should call RandomSeed(Data, SizeOf(Data))
    // instead, where Date contains i.e. user generated (Human) input.
    t := RandomSystemTime;
    for i := Low(FRegister) to High(FRegister) do
    begin
      FRegister[i] := FRegister[i] xor Byte(t);
      t := t shl 1 or t shr 31;
    end;
  end;
  for i := Low(FRegister) to High(FRegister) do
    DoProcess;
  FCounter := 0;
end;

procedure DoInit;
begin
  DoRandomBuffer := DoBuffer;
  DoRandomSeed := DoSeed;
  DoSeed('', 0);
end;

procedure DoDone;
begin
  try
    if FHash <> nil then
      FHash.Free;
  except
  end;
  FHash := nil;
  FillChar(FRegister, SizeOf(FRegister), 0);
  FCounter := 0;
end;

{$IFDEF RESTORE_RANGECHECKS}{$R+}{$ENDIF}
{$IFDEF RESTORE_OVERFLOWCHECKS}{$Q+}{$ENDIF}

initialization
  DoInit;

  {$IFDEF AUTO_PRNG} // see DECOptions.inc
  RandomSeed;
  {$ENDIF AUTO_PRNG}

finalization
  DoDone;

end.
