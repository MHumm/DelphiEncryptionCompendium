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
  Utility functions
}

unit DECUtil;

interface

{$I DECOptions.inc}

uses
  SysUtils, Classes, DECBaseClass, DECTypes;

type
  // Exception Classes

  /// <summary>
  ///   Base exception class for all DEC specific exceptions,
  /// </summary>
  EDECException       = class(Exception)
  public
    {$IFDEF FMXTranslateableExceptions}
    /// <summary>
    ///   Creates the exception instance and makes the exception message translateable
    ///   via Firemonkey's TLang translation mechanism. Normal ressource strings
    ///   are not translated in the same way on mobile platforms as they are on
    ///   Win32/Win64.
    /// </summary>
    /// <param name="ResStringRec">
    ///   Specifies the ressource string which shall be used as exception message.
    ///   Call it like this: .CreateRes(@MyResourceStringName);
    /// </param>
    constructor CreateRes(ResStringRec: PResStringRec); reintroduce; overload;
    /// <summary>
    ///   Creates the exception instance and makes the exception message translateable
    ///   via Firemonkey's TLang translation mechanism. Normal ressource strings
    ///   are not translated in the same way on mobile platforms as they are on
    ///   Win32/Win64.
    /// </summary>
    /// <param name="ResStringRec">
    ///   Specifies the ressource string which shall be used as exception message.
    ///   It may contain format strings like %0:s
    /// </param>
    /// <param name="Args">
    ///   Array with values for the parameters specified in the format string
    /// </param>
    constructor CreateResFmt(ResStringRec: PResStringRec;
                             const Args: array of const); reintroduce; overload;
    {$ENDIF}
  end;

  /// <summary>
  ///   Exception class used when reporting that a class searched in a list is
  ///   not contained in that list, e.g. when searching for a non existant
  ///   formatting class.
  /// </summary>
  EDECClassNotRegisteredException = class(EDECException);
  /// <summary>
  ///   Exception class for reporting formatting related exceptions
  /// </summary>
  EDECFormatException = class(EDECException);
  /// <summary>
  ///   Exception class for reporting exceptions related to hash functions
  /// </summary>
  EDECHashException   = class(EDECException);
  /// <summary>
  ///   Exception class for reporting encryption/decryption caused exceptions
  /// </summary>
  EDECCipherException = class(EDECException);

  /// <summary>
  ///   Exception class for reporting the use of abstract things which cannot
  ///   be called directly
  /// </summary>
  EDECAbstractError = class(EDECException)
    /// <summary>
    ///   Create the exception using a meaningfull error message
    /// </summary>
    constructor Create(ClassType: TDECClass); overload;
  end;

  /// <summary>
  ///   Progress Callback used by Cipher and Hash for Stream and File methods
  /// </summary>
  IDECProgress = interface
    ['{64366E77-82FE-4B86-951E-79389729A493}']
    /// <summary>
    ///   Callback used by stream oriented Cipher and Hash functions for reporting
    ///   the progress of the operation
    /// </summary>
    procedure Process(const Min, Max, Pos: Int64); stdcall;
  end;

// Byte Ordering

/// <summary>
///   Reverses all bits in the passed value
/// </summary>
/// <param name="Source">
///   Value who's bits are to be reversed
/// </param>
/// <returns>
///   Representation of Source but with all bits reversed
/// </returns>
function ReverseBits(Source: UInt32): UInt32;

/// <summary>
///   Reverses the order of the bytes contained in the buffer passed in.
///   e.g. 1 2 3 will be 3 2 1 afterwards
/// </summary>
/// <param name="Buffer">
///   Buffer who's contents is to be reversed.
/// </param>
/// <param name="Size">
///   Size of the passed buffer in byte
/// </param>
procedure SwapBytes(var Buffer; Size: Integer);
/// <summary>
///   Reverses the byte order of the passed variable
/// </summary>
/// <param name="Source">
///   value who's byte order shall be reversed
/// </param>
/// <returns>
///   value of the passed vallue with reversed byte order
/// </returns>
function  SwapUInt32(Source: UInt32): UInt32;
/// <summary>
///   Reverses the byte order for all entries of a passed array of UInt32 values
/// </summary>
/// <param name="Source">
///   Data with a layout like an array of UInt32 values for which the byte order
///   of all entries shall be reversed
/// </param>
/// <param name="Dest">
///   In this variable the reversed values will be stored. Layout is like an
///   array of UInt32 values
/// </param>
/// <param name="Count">
///   Number of values to be reversed
/// </param>
procedure SwapUInt32Buffer(const Source; var Dest; Count: Integer);
/// <summary>
///   Reverses the byte order of an Int64 value
/// </summary>
/// <param name="Source">
///   Value who's byte order shall be reversed
/// </param>
/// <returns>
///   Representation of the passed value after reversing its byte order
/// </returns>
function  SwapInt64(Source: Int64): Int64;
/// <summary>
///   Reverses the byte order for all entries of a passed array of Int64 values
/// </summary>
/// <param name="Source">
///   Data with a layout like an array of Int64 values for which the byte order
///   of all entries shall be reversed
/// </param>
/// <param name="Dest">
///   In this variable the reversed values will be stored. Layout is like an
///   array of Int64 values
/// </param>
/// <param name="Count">
///   Number of values to be reversed
/// </param>
procedure SwapInt64Buffer(const Source; var Dest; Count: Integer);

/// <summary>
///   XORs the contents of two passed buffers and stores the result into a 3rd one
/// </summary>
/// <param name="Left">
///   One source buffer of bytes to be XORed
/// </param>
/// <param name="Right">
///   The other source buffer of bytes to be XORed. Buffer size must be equal
///   or bigger than Left
/// </param>
/// <param name="Size">
///   Buffer size in byte.
/// </param>
/// <param name="Dest">
///   Buffer where the result is to be stored in. Must be of equal or bigger
///   size than Left
/// </param>
procedure XORBuffers(const Left, Right; Size: Integer; var Dest);

// Buffer and Data Protection

/// <summary>
///   Fills a given buffer with zeros in a secure way
/// </summary>
/// <param name="Buffer">
///   Buffer to be zeroed. In case of TBytes to be passed as Buf[0]
/// </param>
/// <param name="Size">
///   Buffer size in byte
/// </param>
procedure ProtectBuffer(var Buffer; Size: NativeUInt);
/// <summary>
///   Fills a given stream with zeros in a secure way
/// </summary>
/// <param name="Stream">
///   Stream to be zeroed.
/// </param>
/// <param name="SizeToProtect">
///   Number of bytes of that stream to be zeroed. Starting point is Stream.Position
/// </param>
procedure ProtectStream(Stream: TStream; SizeToProtect: Int64 = 0);
/// <summary>
///   Fills a given byte array with zeros in a secure way and then empties the
///   buffer.
/// </summary>
/// <param name="Source">
///   Byte array to be zeroed. The length of the passed buffer is 0 afterwards!
/// </param>
procedure ProtectBytes(var Source: TBytes);

/// <summary>
///   Overwrites the string's contents in a secure way and returns an empty string.
/// </summary>
/// <param name="Source">
///   String to be safely overwritten
/// </param>
procedure ProtectString(var Source: string); overload;

{$IFDEF MSWINDOWS}
/// <summary>
///   Overwrites the string's contents in a secure way and returns an empty string.
/// </summary>
/// <param name="Source">
///   String to be safely overwritten
/// </param>
procedure ProtectString(var Source: RawByteString); overload;
{$ENDIF}

{$IFNDEF NEXTGEN}
/// <summary>
///   Overwrites the string's contents in a secure way and returns an empty string.
/// </summary>
/// <param name="Source">
///   String to be safely overwritten
/// </param>
procedure ProtectString(var Source: AnsiString); overload;
/// <summary>
///   Overwrites the string's contents in a secure way and returns an empty string.
/// </summary>
/// <param name="Source">
///   String to be safely overwritten
/// </param>
procedure ProtectString(var Source: WideString); overload;
{$ENDIF}

// Byte/String conversion

/// <summary>
///   Converts a byte array to a RawByteString
/// </summary>
/// <param name="Source">
///   Byte array to be converted into a string. An empty byte array is allowed
///   and results in an empty string.
/// </param>
/// <returns>
///   RawByteString with the same length as Source and all bytes copied over.
///   No conversion of any sort is being applied to the bytes.
/// </returns>
/// <remarks>
///   Not easily replaced by some RTL function as none for TBytes to RawByteString
///   seems to exist
/// </remarks>
function BytesToRawString(const Source: TBytes): RawByteString;

implementation

{$IFDEF FMXTranslateableExceptions}
uses
  FMX.Types, System.TypInfo;
{$ELSE}
uses
  System.TypInfo;
{$ENDIF}

const
{ TODO :
Prüfen warum das eine Konstante ist, die gleich vom Ressourcestring
benutzt wird. Weil es keine Ressorcestrings bei FMX gibt? }
  cAbstractError = 'Abstract Error: %s is not implemented';

resourcestring
  sAbstractError = cAbstractError;

{$IFDEF MSWINDOWS}
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

constructor EDECAbstractError.Create(ClassType: TDECClass);
begin
  inherited CreateResFmt(@sAbstractError, [TDECClassList.GetShortClassName(ClassType)]);
end;

const
  // Bit Lookup Table - see 'Bit Twiddling Hacks' by Sean Eron Anderson
  // http://graphics.stanford.edu/~seander/bithacks.html
  ReverseBitLookupTable256: array[0..255] of Byte = ($00, $80, $40, $C0,
   $20, $A0, $60, $E0, $10, $90, $50, $D0, $30, $B0, $70, $F0, $08, $88,
   $48, $C8, $28, $A8, $68, $E8, $18, $98, $58, $D8, $38, $B8, $78, $F8,
   $04, $84, $44, $C4, $24, $A4, $64, $E4, $14, $94, $54, $D4, $34, $B4,
   $74, $F4, $0C, $8C, $4C, $CC, $2C, $AC, $6C, $EC, $1C, $9C, $5C, $DC,
   $3C, $BC, $7C, $FC, $02, $82, $42, $C2, $22, $A2, $62, $E2, $12, $92,
   $52, $D2, $32, $B2, $72, $F2, $0A, $8A, $4A, $CA, $2A, $AA, $6A, $EA,
   $1A, $9A, $5A, $DA, $3A, $BA, $7A, $FA, $06, $86, $46, $C6, $26, $A6,
   $66, $E6, $16, $96, $56, $D6, $36, $B6, $76, $F6, $0E, $8E, $4E, $CE,
   $2E, $AE, $6E, $EE, $1E, $9E, $5E, $DE, $3E, $BE, $7E, $FE, $01, $81,
   $41, $C1, $21, $A1, $61, $E1, $11, $91, $51, $D1, $31, $B1, $71, $F1,
   $09, $89, $49, $C9, $29, $A9, $69, $E9, $19, $99, $59, $D9, $39, $B9,
   $79, $F9, $05, $85, $45, $C5, $25, $A5, $65, $E5, $15, $95, $55, $D5,
   $35, $B5, $75, $F5, $0D, $8D, $4D, $CD, $2D, $AD, $6D, $ED, $1D, $9D,
   $5D, $DD, $3D, $BD, $7D, $FD, $03, $83, $43, $C3, $23, $A3, $63, $E3,
   $13, $93, $53, $D3, $33, $B3, $73, $F3, $0B, $8B, $4B, $CB, $2B, $AB,
   $6B, $EB, $1B, $9B, $5B, $DB, $3B, $BB, $7B, $FB, $07, $87, $47, $C7,
   $27, $A7, $67, $E7, $17, $97, $57, $D7, $37, $B7, $77, $F7, $0F, $8F,
   $4F, $CF, $2F, $AF, $6F, $EF, $1F, $9F, $5F, $DF, $3F, $BF, $7F, $FF);

function ReverseBits(Source: UInt32): UInt32;
begin
  Result := (ReverseBitLookupTable256[Source and $FF] shl 24) or
            (ReverseBitLookupTable256[(Source shr 8) and $FF] shl 16) or
            (ReverseBitLookupTable256[(Source shr 16) and $FF] shl 8) or
            (ReverseBitLookupTable256[(Source shr 24) and $FF]);
end;

procedure SwapBytes(var Buffer; Size: Integer);
{$IFDEF X86ASM}
asm
      CMP     EDX,1
      JLE     @@3
      AND     EAX,EAX
      JZ      @@3
      PUSH    EBX
      MOV     ECX,EDX
      LEA     EDX,[EAX + ECX - 1]
      SHR     ECX,1
@@1:  MOV     BL,[EAX]
      XCHG    BL,[EDX]
      DEC     EDX
      MOV     [EAX],BL
      INC     EAX
      DEC     ECX
      JNZ     @@1
@@2:  POP     EBX
@@3:
end;
{$ELSE !X86ASM}
var
  T: Byte;
  P, Q: PByte;
  i: Integer;
begin
  P := @Buffer;
  Inc(P, Size - 1);
  Q := @Buffer;
  for i := 0 to Size div 2 - 1 do // using P/Q comparison with 'while' breaks some compilers
  begin
    T := Q^;
    Q^ := P^;
    P^ := T;
    Dec(P);
    Inc(Q);
  end;
end;
{$ENDIF !X86ASM}

function SwapUInt32(Source: UInt32): UInt32;
{$IF defined(X86ASM) or defined(X64ASM)}
  asm
  {$IFDEF X64ASM}
    MOV   EAX, ECX
  {$ENDIF X64ASM}
    BSWAP EAX
  end;
{$ELSE PUREPASCAL}
begin
  Result := Source shl 24 or
            Source shr 24 or
            Source shl 8 and $00FF0000 or
            Source shr 8 and $0000FF00;
end;
{$ENDIF PUREPASCAL}

procedure SwapUInt32Buffer(const Source; var Dest; Count: Integer);
{$IFDEF X86ASM}
asm
      TEST    ECX,ECX
      JLE     @Exit
      PUSH    EDI
      SUB     EAX,4
      SUB     EDX,4
@@1:  MOV     EDI,[EAX + ECX * 4]
      BSWAP   EDI
      MOV     [EDX + ECX * 4],EDI
      DEC     ECX
      JNZ     @@1
      POP     EDI
@Exit:
end;
{$ELSE !X86ASM}
var
  i: Integer;
  T: UInt32;
begin
  for i := 0 to Count - 1 do
  begin
    T := TUInt32Array(Source)[i];
    TUInt32Array(Dest)[i] := (T shl 24) or (T shr 24) or
                           ((T shl 8) and $00FF0000) or ((T shr 8) and $0000FF00);
  end;
end;
{$ENDIF !X86ASM}

function SwapInt64(Source: Int64): Int64;
{$IFDEF X86ASM}
asm
      MOV     EDX,Source.DWord[0]
      MOV     EAX,Source.DWord[4]
      BSWAP   EDX
      BSWAP   EAX
end;
{$ELSE !X86ASM}
var
  L, H: Cardinal;
begin
  L := Int64Rec(Source).Lo;
  H := Int64Rec(Source).Hi;
  L := L shl 24 or L shr 24 or L shl 8 and $00FF0000 or L shr 8 and $0000FF00;
  H := H shl 24 or H shr 24 or H shl 8 and $00FF0000 or H shr 8 and $0000FF00;
  Int64Rec(Result).Hi := L;
  Int64Rec(Result).Lo := H;
end;
{$ENDIF !X86ASM}

procedure SwapInt64Buffer(const Source; var Dest; Count: Integer);
{$IFDEF X86ASM}
asm
      TEST    ECX,ECX
      JLE     @Exit
      PUSH    ESI
      PUSH    EDI
      LEA     ESI,[EAX + ECX * 8]
      LEA     EDI,[EDX + ECX * 8]
      NEG     ECX
@@1:  MOV     EAX,[ESI + ECX * 8]
      MOV     EDX,[ESI + ECX * 8 + 4]
      BSWAP   EAX
      BSWAP   EDX
      MOV     [EDI + ECX * 8 + 4],EAX
      MOV     [EDI + ECX * 8],EDX
      INC     ECX
      JNZ     @@1
      POP     EDI
      POP     ESI
@Exit:
end;
{$ELSE !X86ASM}
var
  H, L: Cardinal;
  i: Integer;
begin
  for i := 0 to Count - 1 do
  begin
    H := TUInt32Array(Source)[i * 2    ];
    L := TUInt32Array(Source)[i * 2 + 1];
    TUInt32Array(Dest)[i * 2    ] := L shl 24 or L shr 24 or L shl 8 and $00FF0000 or L shr 8 and $0000FF00;
    TUInt32Array(Dest)[i * 2 + 1] := H shl 24 or H shr 24 or H shl 8 and $00FF0000 or H shr 8 and $0000FF00;
  end;
end;
{$ENDIF !X86ASM}

procedure XORBuffers(const Left, Right; Size: Integer; var Dest);
// Dest^ = Source1^ xor Source2^
// Buffers must have the same size!
{$IFDEF X86ASM}
asm
      AND     ECX,ECX
      JZ      @@5
      PUSH    ESI
      PUSH    EDI
      MOV     ESI,EAX
      MOV     EDI,Dest
@@1:  TEST    ECX,3
      JNZ     @@3
@@2:  SUB     ECX,4
      JL      @@4
      MOV     EAX,[ESI + ECX]
      XOR     EAX,[EDX + ECX]
      MOV     [EDI + ECX],EAX
      JMP     @@2
@@3:  DEC     ECX
      MOV     AL,[ESI + ECX]
      XOR     AL,[EDX + ECX]
      MOV     [EDI + ECX],AL
      JMP     @@1
@@4:  POP     EDI
      POP     ESI
@@5:
end;
{$ELSE !X86ASM}
var
  P, Q, D: PByte;
  i: Integer;
begin
  P := @Left;
  Q := @Right;
  D := @Dest;
  for i := 0 to Size - 1 do
  begin
    D^ := P^ xor Q^;
    Inc(P);
    Inc(Q);
    Inc(D);
  end;
end;
{$ENDIF !X86ASM}

const
  WipeCount = 4;
  WipeBytes: array[0..WipeCount - 1] of Byte = (
    $55, // 0101 0101
    $AA, // 1010 1010
    $FF, // 1111 1111
    $00  // 0000 0000
  );

procedure ProtectBuffer(var Buffer; Size: NativeUInt);
var
  Count: Integer;
begin
  if Size > 0 then
  begin
    for Count := 0 to WipeCount - 1 do
      FillChar(Buffer, Size, WipeBytes[Count]);
  end;
end;

procedure ProtectStream(Stream: TStream; SizeToProtect: Int64 = 0);
const
  BufferSize = 512;
var
  Buffer: String;
  Count, Bytes, Size: Integer;
  Position: Integer;
begin
  Position := Stream.Position;
  Size := Stream.Size;
  if SizeToProtect <= 0 then
  begin
    SizeToProtect := Size;
    Position := 0;
  end else
  begin
    Dec(Size, Position);
    if SizeToProtect > Size then
      SizeToProtect := Size;
  end;
  SetLength(Buffer, BufferSize);
  for Count := 0 to WipeCount -1 do
  begin
    Stream.Position := Position;
    Size := SizeToProtect;
    FillChar(Buffer[Low(Buffer)], BufferSize, WipeBytes[Count]);
    while Size > 0 do
    begin
      Bytes := Size;
      if Bytes > BufferSize then
        Bytes := BufferSize;
      Stream.Write(Buffer[Low(Buffer)], Bytes);
      Dec(Size, Bytes);
    end;
  end;
end;

procedure ProtectBytes(var Source: TBytes);
begin
  if (Source <> nil) and (Length(Source) > 0) then
  begin
    ProtectBuffer(Pointer(Source)^, Length(Source));
    SetLength(Source, 0);
  end;
end;

procedure ProtectString(var Source: string); overload;
begin
  if Length(Source) > 0 then
  begin
    UniqueString(Source);
    ProtectBuffer(Pointer(Source)^, Length(Source) * SizeOf(Source[Low(Source)]));
    Source := '';
  end;
end;

{$IFDEF MSWINDOWS}
procedure ProtectString(var Source: RawByteString); overload;
begin
  if Length(Source) > 0 then
  begin
    // UniqueString(Source); cannot be called with a RawByteString as there is
    // no overload for it
    TUniqueStringHelper.UniqueString<RawByteString>(Source);
    ProtectBuffer(Pointer(Source)^, Length(Source) * SizeOf(Source[Low(Source)]));
    Source := '';
  end;
end;
{$ENDIF}

{$IFNDEF NEXTGEN}
procedure ProtectString(var Source: AnsiString); overload;
begin
  if Length(Source) > 0 then
  begin
    UniqueString(Source);
    ProtectBuffer(Pointer(Source)^, Length(Source) * SizeOf(Source[Low(Source)]));
    Source := '';
  end;
end;

procedure ProtectString(var Source: WideString); overload;
begin
  if Length(Source) > 0 then
  begin
    UniqueString(Source); // for OS <> Win, WideString is not RefCounted on Win
    ProtectBuffer(Pointer(Source)^, Length(Source) * SizeOf(Source[Low(Source)]));
    Source := '';
  end;
end;
{$ENDIF}

function BytesToRawString(const Source: TBytes): RawByteString;
begin
  SetLength(Result, Length(Source));

  if (Length(Source) > 0) then
  begin
    // determine lowest string index for handling of ZeroBasedStrings
    Move(Source[0], Result[Low(result)], length(Source));
  end;
end;

{ EDECException }

{$IFDEF FMXTranslateableExceptions}
constructor EDECException.CreateRes(ResStringRec: PResStringRec);
begin
  inherited Create(Translate(LoadResString(ResStringRec)));
end;

constructor EDECException.CreateResFmt(ResStringRec: PResStringRec;
  const Args: array of const);
begin
  inherited Create(Format(Translate(LoadResString(ResStringRec)), Args));
end;
{$ENDIF}

end.

