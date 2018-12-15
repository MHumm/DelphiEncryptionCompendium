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
///   This unit provides a standardisized way for applying format conversions to data
/// </summary>
unit DECFormat;

interface

{$I DECOptions.inc}

uses
  SysUtils, Classes, DECBaseClass, DECFormatBase, DECUtil;

type
  /// <summary>
  ///   wrapper (allows omitting DECFormatBase in user code)
  /// </summary>
  TDECFormat        = DECFormatBase.TDECFormat;
  /// <summary>
  ///   wrapper (allows omitting DECFormatBase in user code)
  /// </summary>
  TDECFormatClass   = DECFormatBase.TDECFormatClass;
  /// <summary>
  ///   wrapper (allows omitting DECFormatBase in user code)
  /// </summary>
  TFormat_Copy      = DECFormatBase.TFormat_Copy;

  TFormat_HEX       = class;
  TFormat_HEXL      = class;

  TFormat_Base16    = class;
  TFormat_Base16L   = class;

  TFormat_DECMIME32 = class;

  TFormat_Base64    = class;
  TFormat_MIME64    = class;

  TFormat_Radix64   = class;
  TFormat_PGP       = class;

  TFormat_UU        = class;
  TFormat_XX        = class;
  TFormat_ESCAPE    = class;

  /// <summary>
  ///   Hexadecimal in Uppercase, Base16, see http://tools.ietf.org/html/rfc4648
  /// </summary>
  TFormat_HEX = class(TDECFormat)
  protected
    class procedure DoEncode(const Source; var Dest: TBytes; Size: Integer); override;
    class procedure DoDecode(const Source; var Dest: TBytes; Size: Integer); override;
    class function DoIsValid(const Data; Size: Integer): Boolean; override;
  public
    class function CharTableBinary: TBytes; virtual;
  end;

  /// <summary>
  ///   Hexadecimal in lowercase, Base16, see http://tools.ietf.org/html/rfc4648
  /// </summary>
  TFormat_HEXL = class(TFormat_HEX)
  public
    class function CharTableBinary: TBytes; override;
  end;

  /// <summary>
  ///   Same as TFormat_HEX, use TFormat_HEX instead
  /// </summary>
  TFormat_Base16 = class(TFormat_HEX)
  end deprecated 'Use TFormat_HEX instead';

  /// <summary>
  ///   Same as TFormat_HEXL, use TFormat_HEXL instead
  /// </summary>
  TFormat_Base16L = class(TFormat_HEXL)
  end deprecated 'Use TFormat_HEXL instead';

  /// <summary>
  ///   Proprietary variant of MINE32, kept for backwards compatibility with old
  ///   DEC versions
  /// </summary>
  /// <remarks>
  ///   This formatting should only be used for supporting legacy projects which
  ///   already use this format. It is being considered to be more or less deprecated.
  /// </remarks>
  TFormat_DECMIME32 = class(TFormat_HEX)
  protected
    /// <summary>
    ///   Encodes data passed to this method in the proprietary DECMIME32 format.
    /// </summary>
    /// <remarks>
    ///   This formatting should only be used for supporting legacy projects which
    ///   already use this format. It is being considered to be more or less deprecated.
    /// </remarks>
    class procedure DoEncode(const Source; var Dest: TBytes; Size: Integer); override;
    /// <summary>
    ///   Decodes data passed to this method in the proprietary DECMIME32 format
    ///   into an array of normal bytes.
    /// </summary>
    /// <remarks>
    ///   This formatting should only be used for supporting legacy projects which
    ///   already use this format. It is being considered to be more or less deprecated.
    /// </remarks>
    class procedure DoDecode(const Source; var Dest: TBytes; Size: Integer); override;
    /// <summary>
    ///   Checks if certain data adheres to the rules for this formatting.
    /// </summary>
    /// <remarks>
    ///   This formatting should only be used for supporting legacy projects which
    ///   already use this format. It is being considered to be more or less deprecated.
    /// </remarks>
    class function DoIsValid(const Data; Size: Integer): Boolean; override;

  public
    class function CharTableBinary: TBytes; override;
  end;

  /// <summary>
  ///   Same as DECMIME32, which itsself should only be used for legacy projects
  /// </summary>
  TFormat_MIME32 = class(TFormat_DECMIME32)
  end deprecated 'Use TFormat_DECMIME32 instead';

  /// <summary>
  ///   Base64 (without soft wraps), see http://tools.ietf.org/html/rfc4648
  /// </summary>
  TFormat_Base64 = class(TFormat_HEX)
  protected
    class procedure DoEncode(const Source; var Dest: TBytes; Size: Integer); override;
    class procedure DoDecode(const Source; var Dest: TBytes; Size: Integer); override;
  public
    class function CharTableBinary: TBytes; override;
  end;

  /// <summary>
  ///   Same as TFormat_Base64, use TFormat_Base64 instead, kept for backwards
  ///   compatibility only
  /// </summary>
  TFormat_MIME64 = class(TFormat_Base64)
  end deprecated 'Use TFormat_Base64 instead';

  /// <summary>
  ///   OpenPGP/PGP Base64 with 24-bit Checksums, see http://tools.ietf.org/html/rfc4880
  /// </summary>
  TFormat_Radix64 = class(TFormat_Base64)
  /// <summary>
  ///   Here the section needs to be private so that the variable can be accessed
  ///   for initialization in the initialization section, which is needed since
  ///   all functionality of the class is implemented as class methods
  /// </summary>
  private
    /// <summary>
    ///   Maximum number of chars for one line of message text
    /// </summary>
    class var FCharsPerLine : UInt32;
  protected
    class function DoExtractCRC(const Data; var Size: Integer): UInt32;
    /// <summary>
    ///   If the data given exceeds FCharsPerLine, means the maximum allowed
    ///   line lenth, a CR/LF pair needs to be inserted at that position.
    /// </summary>
    /// <param name="Source">
    ///   Data to insert a CR/LF into if necessary
    /// </param>
    /// <param name="Dest">
    ///   In this byte array the processed data will be returned
    /// </param>
    /// <param name="LineLength">
    ///   Maximum length of a line in byte. At this position the CR/LF will be
    ///   inserted if the source passed in exceeds this length.
    /// </param>
    class procedure InsertCRLF(const Source: TBytes; var Dest: TBytes; LineLength: Integer);
    class procedure DoEncode(const Source; var Dest: TBytes; Size: Integer); override;
    class procedure DoDecode(const Source; var Dest: TBytes; Size: Integer); override;
  public
    /// <summary>
    ///   Changes the number of chars after which a line break is being added
    /// </summary>
    /// <param name="Value">
    ///   Maximum number of chars for a single line. Values < 1 result in an
    ///   EArgumentOutOfRangeException being raised
    /// </param>
    class procedure SetCharsPerLine(const Value: UInt32);
    /// <summary>
    ///   Returns the number of chars after which a line break will be introduced
    /// </summary>
    /// <returns>
    ///   Maximum number of chars per line
    /// </returns>
    /// <remarks>
    ///   Cannot be a property, as properties cannot access class vars
    /// </remarks>
    class function GetCharsPerLine: UInt32;
  end;

  /// <summary>
  ///   Same as TFormat_Radix64, use TFormat_Radix64 instead, kept for backwards
  ///   compatibility only
  /// </summary>
  TFormat_PGP = class(TFormat_Radix64)
  end deprecated 'Use TFormat_Radix64 instead';

  /// <summary>
  ///   Unix UU format
  /// </summary>
  TFormat_UU = class(TDECFormat)
  protected
    class procedure DoEncode(const Source; var Dest: TBytes; Size: Integer); override;
    class procedure DoDecode(const Source; var Dest: TBytes; Size: Integer); override;
    class function DoIsValid(const Data; Size: Integer): Boolean; override;
  public
    class function CharTableBinary: TBytes; virtual;
  end;

  /// <summary>
  ///   Unix XX format
  /// </summary>
  TFormat_XX = class(TFormat_UU)
  public
    class function CharTableBinary: TBytes; override;
  end;

  /// <summary>
  ///   Escaped format
  /// </summary>
  TFormat_ESCAPE = class(TDECFormat)
  protected
    class procedure DoEncode(const Source; var Dest: TBytes; Size: Integer); override;
    class procedure DoDecode(const Source; var Dest: TBytes; Size: Integer); override;
  public
    class function CharTableBinary: TBytes; virtual;
  end;

implementation

uses
  DECCRC; // needed by TFormat_Radix64

resourcestring
  sInvalidStringFormat  = 'Input is not an valid %s format';

class function TFormat_HEX.CharTableBinary: TBytes;
begin
  SetLength(result, 48);
  // special and skipped chars
  // '0123456789ABCDEFX$ abcdefhHx()[]{},;:-_/\*+"'''+CHR(9)+CHR(10)+CHR(13);

  result := [$30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $41, $42, $43,
             $44, $45, $46, $58, $24, $20, $61, $62, $63, $64, $65, $66, $68,
             $48, $78, $28, $29, $5B, $5D, $7B, $7D, $2C, $3B, $3A, $2D, $5F,
             $2F, $5C, $2A, $2B, $22, $27, $09, $0A, $0D];
end;

class procedure TFormat_HEX.DoEncode(const Source; var Dest: TBytes; Size: Integer);
var
  S     : PByte;
  Table : TBytes;
  i     : Integer;
begin
  if Size <= 0 then Exit;
  SetLength(Dest, Size * 2);

  Table := CharTableBinary;

  S     := PByte(@Source);
  i     := 0;

  while Size > 0 do
  begin
    Dest[i]     := Table[S^ shr  4];
    Dest[i + 1] := Table[S^ and $F];

    Inc(S);
    Dec(Size);
    Inc(i, 2);
  end;
end;

class procedure TFormat_HEX.DoDecode(const Source; var Dest: TBytes; Size: Integer);
var
  S: PByte;
  D: PByte;
  T: TBytes;
  I,P: Integer;

  HasIdent: Boolean;
begin
  SetLength(Dest, 0);
  if Size <= 0 then Exit;
  SetLength(Dest, Size div 2); //  + 1);

  T := CharTableBinary;

  D := PByte(Dest);
  S := PByte(@Source);
  I := 0;
  HasIdent := False;
  while Size > 0 do
  begin
    P := TableFindBinary(S^, T, 18);
    if P < 0 then P := TableFindBinary(UpCaseBinary(S^), T, 16);
    if P < 0 then
      raise EDECException.CreateFmt(sInvalidStringFormat, [self.GetShortClassName]);
    Inc(S);
    if P >= 0 then
      if P > 16 then
      begin
        if not HasIdent then
        begin
          HasIdent := True;
          I := 0;
          D := PByte(Dest);
        end;
      end
      else
      begin
        if Odd(I) then
        begin
          D^ := D^ or P;
          Inc(D);
        end
        else
          D^ := P shl 4;
        Inc(I);
      end;
    Dec(Size);
  end;
end;

class function TFormat_HEX.DoIsValid(const Data; Size: Integer): Boolean;
var
  T: TBytes;
  S: PByte;
begin
  if not odd(Size) then
  begin
    Result := True;
    T := CharTableBinary;
    S := @Data;
    while Result and (Size > 0) do
    begin
      if TableFindBinary(S^, T, length(T)) >= 0 then
      begin
        Inc(S);
        Dec(Size);
      end
      else
        Result := False;
    end;
  end
  else
    result := false;
end;

class function TFormat_HEXL.CharTableBinary: TBytes;
begin
  SetLength(result, 48);
  // special and skipped chars
  // '0123456789abcdefX$ ABCDEFhHx()[]{},;:-_/\*+"'''+CHR(9)+CHR(10)+CHR(13);

  result := [$30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $61, $62, $63,
             $64, $65, $66, $68, $58, $24, $20, $41, $42, $43, $44, $45, $46,
             $48, $78, $28, $29, $5B, $5D, $7B, $7D, $2C, $3B, $3A, $2D, $5F,
             $2F, $5C, $2A, $2B, $22, $27, $09, $0A, $0D];
end;

class function TFormat_DECMIME32.CharTableBinary: TBytes;
begin
  // special and skipped chars
  // 'abcdefghijklnpqrstuwxyz123456789 =$()[]{},;:-_\*"'''+CHR(9)+CHR(10)+CHR(13);
  SetLength(result, 53);
  result := [$61, $62, $63, $64, $65, $66, $67, $68, $69, $6A, $6B, $6C, $6E, $70,
             $71, $72, $73, $74, $75, $77, $78, $79, $7A, $31, $32, $33, $34, $35,
             $36, $37, $38, $39, $20, $3D, $24, $28, $29, $5B, $5D, $7B, $7D, $2C,
             $3B, $3A, $2D, $5F, $5C, $2A, $22, $27, $09, $0A, $0D];
end;

class procedure TFormat_DECMIME32.DoEncode(const Source; var Dest: TBytes; Size: Integer);
var
  T   : TBytes;
  Src : TBytes;
  S, D: PByte;
  i, n: Integer;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  // The passed in source parameter has to be converted into an array with
  // added additional 0 value. This is because in the original form a string was
  // being passed in as source parameter, which automatically contained a #00 at
  // the end and depending on length of the data passed in, the @S[i shr 3] index
  // calculation can result in an index which represents the last byte of the
  // source parameter. That one is accessed as PWord then which results in
  // reading the first byte behind that source parameter as well! This led to
  // wrong data errors in the unit tests.
  SetLength(Src, Size + 1);
  Move(Source, Src[0], Size);
  Src[length(Src)-1] := 0;

  Size := Size * 8;
  SetLength(Dest, Size div 5 + 5);

  D := @Dest[0];
  T := CharTableBinary;
  S := @Src[0];

  i := 0; n := 0;
  while i < Size do
  begin
    D^ := T[PWord(@S[i shr 3])^ shr (i and $7) and $1F];

    Inc(D);
    Inc(i, 5);

    Inc(n);
  end;

  SetLength(Dest, n);
  SetLength(Src, 0);
end;

class function TFormat_DECMIME32.DoIsValid(const Data; Size: Integer): Boolean;
var
  T: TBytes;
  S: PByte;
begin
  Result := True;
  T := CharTableBinary;
  S := @Data;
  while Result and (Size > 0) do
  begin
    if TableFindBinary(S^, T, length(T)) >= 0 then
    begin
      Inc(S);
      Dec(Size);
    end
    else
      Result := False;
  end;
end;

class procedure TFormat_DECMIME32.DoDecode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte;
  D: PByte;
  i, V: Integer;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  Size := Size * 5;
  SetLength(Dest, Size div 8);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  FillChar(D^, Length(Dest), 0);
  i := 0;

  while i < Size do
  begin
    V := TableFindBinary(S^, T, 32);
    if V < 0 then
      V := TableFindBinary(UpCaseBinary(S^), T, 32);
    if V >= 0 then
    begin
      PWord(@D[i shr 3])^ := PWord(@D[i shr 3])^ or (V shl (i and $7));
      Inc(i, 5);
    end
    else
      Dec(Size, 5);
    Inc(S);
  end;

  SetLength(Dest, Size div 8);
end;

class function TFormat_Base64.CharTableBinary: TBytes;
begin
  //  'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' +
  //  ' $()[]{},;:-_\*"'''+CHR(9)+CHR(10)+CHR(13); // special and skipped chars
  SetLength(result, 85);
  result := [$41, $42, $43, $44, $45, $46, $47, $48, $49, $4A, $4B, $4C, $4D,
             $4E, $4F, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $5A,
             $61, $62, $63, $64, $65, $66, $67, $68, $69, $6A, $6B, $6C, $6D,
             $6E, $6F, $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, $7A,
             $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $2B, $2F, $3D,
             $20, $24, $28, $29, $5B, $5D, $7B, $7D, $2C, $3B, $3A, $2D, $5F,
             $5C, $2A, $22, $27, $09, $0A, $0D];
end;

class procedure TFormat_Base64.DoEncode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte;
  D: PByte;
  B: UInt32;
  i: Integer;
  n: Integer;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  SetLength(Dest, Size * 4 div 3 + 4);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  n := 0;
  while Size >= 3 do
  begin
    Dec(Size, 3);
    B := Byte(S[0]) shl 16 or Byte(S[1]) shl 8 or Byte(S[2]);
    D[0] := T[B shr 18 and $3F];
    D[1] := T[B shr 12 and $3F];
    D[2] := T[B shr  6 and $3F];
    D[3] := T[B        and $3F];
    Inc(D, 4);
    S := @S[3];
    Inc(n, 4);
  end;

  while Size > 0 do
  begin
    B := 0;
    for i := 0 to 2 do
    begin
      B := B shl 8;
      if Size > 0 then
      begin
        B := B or Byte(S[0]);
        S := @S[1];
      end;
      Dec(Size);
    end;
    for i := 3 downto 0 do
    begin
      if Size < 0 then
      begin
        D[i] := T[64];
        Inc(Size);
      end
      else
        D[i] := T[B and $3F];
      B := B shr 6;
    end;
    Inc(D, 4);
    Inc(n, 4);
  end;

  // original calculation was substract dest ptr d - start of dest
  SetLength(Dest, n);
end;

class procedure TFormat_Base64.DoDecode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte;
  D, L: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  B: UInt32;
  i, j, n: Integer;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  SetLength(Dest, Size);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  Move(Source, Dest[0], Size);

  L := S + Size;
  j := 0;
  n := 0;
  while S < L do
  begin
    B := 0;
    j := 4;
    while (j > 0) and (S < L) do
    begin
      i := TableFindBinary(S^, T, 65);
      Inc(S);
      if i >= 0 then
      begin
        if i < 64 then
        begin
          B := B shl 6 or Byte(i);
          Dec(j);
        end
        else
          L := S;
      end;
    end;
    if j > 0 then
    begin
      if j >= 4 then
      begin
        j := 0;
        Break;
      end
      else
        B := B shl (6 * j);
    end;
    i := 2;
    while i >= 0 do
    begin
      D[i] := Byte(B);
      B := B shr 8;
      Dec(i);
    end;
    Inc(D, 3);
    Inc(n, 3);
  end;

  // PAnsiChar(D) - PAnsiChar(Dest) - j
  SetLength(Dest, n-j);
end;

class function TFormat_Radix64.DoExtractCRC(const Data; var Size: Integer): UInt32;
var
  L: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  C: Byte;
  R: TBytes;
begin
  Result := $FFFFFFFF;
  C := CharTableBinary[64]; // get padding char, per default '='
  L := PByte(@Data) + Size;
  while L <> @Data do
  begin
    if L^ = C then
      Break
    else
      Dec(L); // scan reverse for padding char
  end;
  if L - PByte(@Data) >= Size - 5 then // remaining chars must be > 4, e.g. '=XQRT'
  try
    Inc(L);
    inherited DoDecode(L^, R, Size - (L - PByte(@Data)));
    if Length(R) >= 3 then
    begin
      Result := 0;
      Move(R[0], Result, 3);
      Size := L - PByte(@Data);
    end;
  except
  end;
end;

class function TFormat_Radix64.GetCharsPerLine: UInt32;
begin
  result := FCharsPerLine;
end;

class procedure TFormat_Radix64.InsertCRLF(const Source: TBytes; var Dest: TBytes; LineLength: Integer);
var
  S, D: PByte;
  i: Integer;
begin
  i := Length(Source);
  if (LineLength <= 0) or (i <= LineLength) then
  begin
    SetLength(Dest, i);
    Move(Source[0], Dest[0], i);
    Exit;
  end;

  SetLength(Dest, i + i * 2 div LineLength + 2);

  S := @Source[0];
  D := @Dest[0];

  repeat
    Move(S^, D^, LineLength);
    Inc(S, LineLength);
    Inc(D, LineLength);
    D^ := Ord(#13);
    Inc(D);
    D^ := Ord(#10);
    Inc(D);
    Dec(i, LineLength);
  until i < LineLength;

  Move(S^, D^, i);
  Inc(D, i);

  SetLength(Dest, PByte(D) - PByte(Dest));
end;

class procedure TFormat_Radix64.SetCharsPerLine(const Value: UInt32);
begin
  assert(Value > 0, 'Invalid number of chars per line: ' + IntToStr(Value));

  if (Value > 0) then
    FCharsPerLine := Value
  else
    raise EArgumentOutOfRangeException.Create('Invalid number of chars per line: ' +
                                              IntToStr(Value));
end;

//procedure TFormat_Radix64.SetCharsPerLine(const Value: UInt32);
//begin
//  if (Value > 0) then
//    FCharsPerLine := Value
//  else
//{ TODO : Exception werfen! }
//    ;
//end;

class procedure TFormat_Radix64.DoEncode(const Source; var Dest: TBytes; Size: Integer);
var
  TempData : TBytes;
  CRC      : UInt32;
  CRCData  : TBytes;
  Position : Integer;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  // use Base64
  inherited DoEncode(Source, TempData, Size);

  // split lines
  InsertCRLF(TempData, Dest, FCharsPerLine);
  SetLength(TempData, 0);

  CRC := CRCCalc(CRC_24, Source, Size); // calculate 24-bit Checksum
  SwapBytes(CRC, 3); // PGP use Big Endian

  // check and insert LF if needed
  Position := Length(Dest) - 1; // last char
  if Dest[Position] <> $0A then
  begin
    // insert CR needed, CRC must be in the next line
    Position := Length(Dest);
    SetLength(Dest, Position + 2);
    Dest[Position]   := $0D; // append CR
    Dest[Position+1] := $0A; // append LF
  end;

  // encode CRC with Base64 too
  inherited DoEncode(CRC, CRCData, 3);

  // if CRC is too long insert CRLF. -1 to compensate the later added = char
  InsertCRLF(CRCData, TempData, FCharsPerLine - 1);
  CRCData := TempData;

  // append encoded CRC
  Position := Length(Dest);
  SetLength(Dest, Position + 1 + Length(CRCData));
  Dest[Position] := Ord('=');
  Move(CRCData[0], Dest[Position + 1], Length(CRCData));
end;

class procedure TFormat_Radix64.DoDecode(const Source; var Dest: TBytes; Size: Integer);
var
  CRC: UInt32;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  CRC := DoExtractCRC(Source, Size);
  inherited DoDecode(Source, Dest, Size);

  if CRC <> $FFFFFFFF then // check CRC if found
  begin
    SwapBytes(CRC, 3);
//    if CRC <> CRCCalc(CRC_24, Dest[0], Size) then
    if CRC <> CRCCalc(CRC_24, Dest[0], Length(Dest)) then
      raise EDECFormatException.CreateResFmt(@sInvalidStringFormat, [self.GetShortClassName]);
  end;
end;

class function TFormat_UU.CharTableBinary: TBytes;
begin
  // '`!"#$%&''()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_' +
  // ' '+CHR(9)+CHR(10)+CHR(13);

  SetLength(result, 68);
  result := [$60, $21, $22, $23, $24, $25, $26, $27, $28, $29, $2A, $2B, $2C,
             $2D, $2E, $2F, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39,
             $3A, $3B, $3C, $3D, $3E, $3F, $40, $41, $42, $43, $44, $45, $46,
             $47, $48, $49, $4A, $4B, $4C, $4D, $4E, $4F, $50, $51, $52, $53,
             $54, $55, $56, $57, $58, $59, $5A, $5B, $5C, $5D, $5E, $5F, $20,
             $09, $0A, $0D];
end;

class procedure TFormat_UU.DoEncode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte;
  D: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  L, i: Integer;
  B: Cardinal;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  SetLength(Dest, Size * 4 div 3 + Size div 45 + 10);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  while Size > 0 do
  begin
    L := Size;
    if L > 45 then
      L := 45;
    Dec(Size, L);
    D^ := T[L];
    while L > 0 do
    begin
      B := 0;
      for i := 0 to 2 do
      begin
        B := B shl 8;
        if L > 0 then
        begin
          B := B or S^;
          Inc(S);
        end;
        Dec(L);
      end;
      for i := 4 downto 1 do
      begin
        D[i] := T[B and $3F];
        B := B shr 6;
      end;
      Inc(D, 4);
    end;
    Inc(D);
  end;

  SetLength(Dest, PByte(D) - PByte(Dest));
end;

class procedure TFormat_UU.DoDecode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte;
  D, L: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  i, E: Integer;
  B: UInt32;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  SetLength(Dest, Size);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  L := PByte(S) + Size;

  repeat
    Size := TableFindBinary(S^, T, 64);
    if (Size < 0) or (Size > 45) then
      raise EDECException.CreateResFmt(@sInvalidStringFormat, [self.GetShortClassName]);
    Inc(S);
    while Size > 0 do
    begin
      B := 0;
      i := 4;
      while (i > 0) and (S <= L) do
      begin
        E := TableFindBinary(S^, T, 64);
        if E >= 0 then
        begin
          B := B shl 6 or Byte(E);
          Dec(i);
        end;
        Inc(S);
      end;
      i := 2;
      repeat
        D[i] := Byte(B);
        B    := B shr 8;
        Dec(i);
      until i < 0;
      if Size > 3 then
        Inc(D, 3)
      else
        Inc(D, Size);
      Dec(Size, 3);
    end;
  until S >= L;

  SetLength(Dest, PByte(D) - PByte(Dest));
end;

class function TFormat_UU.DoIsValid(const Data; Size: Integer): Boolean;
var
  T: TBytes;
  S: PByte;
  Len, P, i: Integer;
begin
  Result := False;
  T := CharTableBinary;
  Len := Length(T);
  S := @Data;
  P := 0;

  while Size > 0 do
  begin
    i := TableFindBinary(S^, T, Len);
    if i >= 0 then
    begin
      Dec(Size);
      Inc(S);
      if P = 0 then
      begin
        if i > 45 then
          Exit;
        P := (i * 4 + 2) div 3;
      end
      else
        if i < 64 then
          Dec(P);
    end
    else
      Exit;
  end;

  if P <> 0 then
    Exit;

  Result := True;
end;

class function TFormat_XX.CharTableBinary: TBytes;
begin
  // '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz' +
  // ' "()[]'''+CHR(9)+CHR(10)+CHR(13);
  SetLength(result, 74);
  result := [$2B, $2D, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39, $41,
             $42, $43, $44, $45, $46, $47, $48, $49, $4A, $4B, $4C, $4D, $4E,
             $4F, $50, $51, $52, $53, $54, $55, $56, $57, $58, $59, $5A, $61,
             $62, $63, $64, $65, $66, $67, $68, $69, $6A, $6B, $6C, $6D, $6E,
             $6F, $70, $71, $72, $73, $74, $75, $76, $77, $78, $79, $7A, $20,
             $22, $28, $29, $5B, $5D, $27, $09, $0A, $0D];
end;

var
  // Initlialized in initialization section, cannot be const because of the
  // TBytes requirement
  ESCAPE_CodesL: TBytes; //array[0..6] of Byte = ($61, $62, $74, $6E, $76, $66, $72);
  ESCAPE_CodesU: TBytes; //array[0..6] of Byte = ($41, $42, $54, $4E, $56, $46, $52);

class function TFormat_ESCAPE.CharTableBinary: TBytes;
begin
  Result := TFormat_HEX.CharTableBinary;
end;

class procedure TFormat_ESCAPE.DoEncode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte;
  D: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  i: Integer;
begin
  SetLength(Dest, 0);
  if Size <= 0 then
    Exit;

  SetLength(Dest, Size + 8);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  i := Size;

  while Size > 0 do
  begin
    if i <= 0 then
    begin
      i := D - PByte(Dest);
      SetLength(Dest, i + Size + 8);
      D := PByte(Dest) + i;
      i := Size;
    end;
    if (S^ < 32) or (S^ > $7F) then
    begin
      if (S^ >= 7) and (S^ <= 13) then
      begin
        D^ := $5C; // \-Zeichen
        Inc(D);
        D^ := ESCAPE_CodesL[S^ - 7];
        Inc(D);
        Dec(i, 2);
      end
      else
      begin
        D^ := $5C; // \ char
        Inc(D);
        D^ := $78; // x
        Inc(D);
        D^ := T[S^ shr 4];
        Inc(D);
        D^ := T[S^ and $F];
        Inc(D);
        Dec(i, 4);
      end
    end
    else
    begin
      // S^is \ char?
      if S^ = $5C then
      begin
        D^ := $5C; // \ char
        Inc(D);
        D^ := $5C; // \ char
        Inc(D);
        Dec(i, 2);
      end
      else
      // S° is " char?
      if S^ = $22 then
      begin
        D^ := $5C; // \ char
        Inc(D);
        D^ := $22; // " char
        Inc(D);
        Dec(i, 2);
      end
      else
      begin
        D^ := S^;
        Inc(D);
        Dec(i);
      end;
    end;
    Dec(Size);
    Inc(S);
  end;

  SetLength(Dest, PByte(D) - PByte(Dest));
end;

class procedure TFormat_ESCAPE.DoDecode(const Source; var Dest: TBytes; Size: Integer);
var
  T: TBytes;
  S: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  D: PByte;
  L: PByte; // 1) to make pointer arithmetic work 2) P/TByteArray is limited to 32768 bytes
  i: Integer;
begin
  if Size <= 0 then
    Exit;
  SetLength(Dest, Size);

  T := CharTableBinary;
  S := @Source;
  D := @Dest[0];

  L := S + Size;

  while S < L do
  begin
    // S^ is \ char?
    if S^ = $5C then
    begin
      Inc(S);
      if S > L then Break;
      // S^ is X char?
      if UpCaseBinary(S^) = $58 then
      begin
        if S + 2 > L then
          raise EDECFormatException.CreateResFmt(@sInvalidStringFormat, [self.GetShortClassName]);
        Inc(S);
        i := TableFindBinary(UpCaseBinary(S^), T, 16);
        if i < 0 then
          raise EDECFormatException.CreateResFmt(@sInvalidStringFormat, [self.GetShortClassName]);
        D^ := i shl 4;
        Inc(S);
        i := TableFindBinary(UpCaseBinary(S^), T, 16);
        if i < 0 then
          raise EDECFormatException.CreateResFmt(@sInvalidStringFormat, [self.GetShortClassName]);
        D^ := D^ or i;
      end
      else
      begin
        i := TableFindBinary(UpCaseBinary(S^), TBytes(ESCAPE_CodesU), 7);
        if i >= 0 then
          D^ := i + 7
        else
          D^ := S^;
      end;
    end
    else
      D^ := S^;
    Inc(D);
    Inc(S);
  end;

  SetLength(Dest, PByte(D) - PByte(Dest));
end;

initialization
  SetLength(ESCAPE_CodesL, 7);
  ESCAPE_CodesL[0] := $61;
  ESCAPE_CodesL[1] := $62;
  ESCAPE_CodesL[2] := $74;
  ESCAPE_CodesL[3] := $6E;
  ESCAPE_CodesL[4] := $76;
  ESCAPE_CodesL[5] := $66;
  ESCAPE_CodesL[6] := $72;

  SetLength(ESCAPE_CodesU, 7);
  ESCAPE_CodesU[0] := $41;
  ESCAPE_CodesU[1] := $42;
  ESCAPE_CodesU[2] := $54;
  ESCAPE_CodesU[3] := $4E;
  ESCAPE_CodesU[4] := $56;
  ESCAPE_CodesU[5] := $46;
  ESCAPE_CodesU[6] := $52;

  TFormat_HEX.RegisterClass(TDECFormat.ClassList);
  TFormat_HEXL.RegisterClass(TDECFormat.ClassList);
  TFormat_DECMIME32.RegisterClass(TDECFormat.ClassList);
  TFormat_Base64.RegisterClass(TDECFormat.ClassList);
  TFormat_Radix64.RegisterClass(TDECFormat.ClassList);
  TFormat_UU.RegisterClass(TDECFormat.ClassList);
  TFormat_XX.RegisterClass(TDECFormat.ClassList);
  TFormat_ESCAPE.RegisterClass(TDECFormat.ClassList);

  // Init the number of chars per line as per RFC 4880 to 76 chars
  TFormat_Radix64.FCharsPerLine := 76;

finalization

  // No need to unregister the hash classes, as the list is being freed
  // in finalization of DECBaseClass unit

//
//
//// prefered hashs
//  THash_MD2.Register;        // 1.5Kb
//  THash_MD4.Register;        // 2.0Kb                           // for fast checksums
//  THash_MD5.Register;        // 2.5Kb
//  THash_SHA.Register;        // 10Kb for SHA,SHA1,SHA256        // strong
//  THash_SHA1.Register;
//  THash_SHA256.Register;
//  THash_SHA384.Register;     // 3.0Kb for SHA384,SHA512
//  THash_SHA512.Register;                                        // variable digest
//  THash_Sapphire.Register;   // 1.0Kb
//
//  THash_Panama.Register;     // 2.0Kb
//  THash_Tiger.Register;      // 12.0kb
//  THash_RipeMD128.Register;  // 4.0Kb
//  THash_RipeMD160.Register;  // 8.0Kb
//  THash_RipeMD256.Register;  // 4.5Kb
//  THash_RipeMD320.Register;  // 9.0Kb
//  THash_Haval128.Register;   // 6.0Kb for all Haval's
//  THash_Haval160.Register;
//  THash_Haval192.Register;
//  THash_Haval224.Register;
//  THash_Haval256.Register;
//  THash_Whirlpool.Register;   // 10.0Kb
//  THash_Whirlpool1.Register;  // 10.0Kb
//  THash_Square.Register;      // 10Kb
//  THash_Snefru128.Register;   // 18Kb
//  THash_Snefru256.Register;   //
//
////  TCipher_Null.Register;
//  TCipher_Blowfish.Register;
//  TCipher_Twofish.Register;
//  TCipher_IDEA.Register;
//  TCipher_CAST256.Register;
//  TCipher_Mars.Register;
//  TCipher_RC4.Register;
//  TCipher_RC6.Register;
//  TCipher_Rijndael.Register;
//  TCipher_Square.Register;
//  TCipher_SCOP.Register;
//  TCipher_Sapphire.Register;
//  TCipher_1DES.Register;
//  TCipher_2DES.Register;
//  TCipher_3DES.Register;
//  TCipher_2DDES.Register;
//  TCipher_3DDES.Register;
//  TCipher_3TDES.Register;
//  TCipher_3Way.Register;
//  TCipher_Cast128.Register;
//  TCipher_Gost.Register;
//  TCipher_Misty.Register;
//  TCipher_NewDES.Register;
//  TCipher_Q128.Register;
//  TCipher_RC2.Register;
//  TCipher_RC5.Register;
//  TCipher_SAFER.Register;
//  TCipher_Shark.Register;
//  TCipher_Skipjack.Register;
//  TCipher_TEA.Register;
//  TCipher_TEAN.Register;


end.
