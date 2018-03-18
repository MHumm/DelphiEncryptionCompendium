{*****************************************************************************

  Delphi Encryption Compendium (DEC)
  Version 6.0

  Copyright (c) 2016 - 2018 Markus Humm (markus [dot] humm [at] googlemail [dot] com)
  Copyright (c) 2008 - 2012 Frederik Winkelsdorf
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
unit DECCipherFormats;

interface

uses
  System.SysUtils, System.Classes,
  DECCipherBase, DECCipherModes, DECUtil, DECFormatBase;

type
  /// <summary>
  ///   Class in which all uncommented methods of TDECCipher have been moved
  ///   until they got properly added by some means
  /// </summary>
  TDECFormattedCipher = class(TDECCipherModes)
  private
    /// <summary>
    ///   Encrypts or decrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to encrypt or to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the encrypted or decrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be encrypted or decrypted
    /// </param>
    /// <param name="CipherProc">
    ///   Callback which either encrypts or decrypts the stream, depending on
    ///   which one is being passed
    /// </param>
    /// <param name="Progress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure DoEncodeDecodeStream(const Source, Dest: TStream; DataSize: Int64;
                                   const CipherProc: TDECCipherCodeEvent;
                                   const Progress: IDECProgress);

    /// <summary>
    ///   Encrypts or decrypts a file and stores the result in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to encrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the encrypted data shall be stored in
    /// </param>
    /// <param name="Proc">
    ///   This method does the actual encrypting or decrypting of the data.
    ///   Usually the Encode or Decode method is being passed here which is
    ///   declared in TDECCipherBase as virtual abstract method and
    ///   implemented in the individual cipher class inheriting from this one
    /// </param>
    /// <param name="Progress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the encryption operation
    /// </param>
    procedure DoEncodeDecodeFile(const SourceFileName, DestFileName: string;
                                 const Proc: TDECCipherCodeEvent;
                                 const Progress: IDECProgress);
  public
    /// <summary>
    ///   Encrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be encrypted
    /// </param>
    /// <returns>
    ///   Byte array with encrypted data
    /// </returns>
    function EncodeBytes(const Source: TBytes): TBytes;
    /// <summary>
    ///   Decrypts the contents of a given byte array
    /// </summary>
    /// <param name="Source">
    ///   Byte array with data to be decrypted
    /// </param>
    /// <returns>
    ///   Byte array with decrypted data
    /// </returns>
    function DecodeBytes(const Source: TBytes): TBytes;

    /// <summary>
    ///   Encrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to encrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the encrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be encrypted
    /// </param>
    /// <param name="Progress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure EncodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const Progress: IDECProgress = nil);

    /// <summary>
    ///   Decrypts the data contained in a given stream
    /// </summary>
    /// <param name="Source">
    ///   Source stream containing the data to decrypt
    /// </param>
    /// <param name="Dest">
    ///   Destination stream, where the decrypted data shall be put in
    /// </param>
    /// <param name="DataSize">
    ///   Number of bytes of Source to be decrypted
    /// </param>
    /// <param name="Progress">
    ///   optional callback for reporting progress of the operation
    /// </param>
    procedure DecodeStream(const Source, Dest: TStream; DataSize: Int64;
                           const Progress: IDECProgress = nil);

    /// <summary>
    ///   Reads the contents of one file, encrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to encrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the encrypted data shall be stored in
    /// </param>
    /// <param name="Progress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the encryption operation
    /// </param>
    procedure EncodeFile(const SourceFileName, DestFileName: string; const Progress: IDECProgress = nil);
    /// <summary>
    ///   Reads the contents of one file, decrypts it and stores it in another file
    /// </summary>
    /// <param name="SourceFileName">
    ///   Path and name of the file to decrypt
    /// </param>
    /// <param name="DestFileName">
    ///   Path and name of the file the decrypted data shall be stored in
    /// </param>
    /// <param name="Progress">
    ///   Optional event which can be passed to get information about the
    ///   progress of the decryption operation
    /// </param>
    procedure DecodeFile(const SourceFileName, DestFileName: string; const Progress: IDECProgress = nil);

    /// <summary>
    ///   Encrypts the contents of the passed unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeString(const Source: string; Format: TDECFormatClass = nil): TBytes; overload;
    /// <summary>
    ///   Encrypts the contents of the passed RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeString(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes; overload;
    /// <summary>
    ///   Decrypts the contents of the passed encrypted unicode string
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeString(const Source: string; Format: TDECFormatClass = nil): TBytes; overload;
    /// <summary>
    ///   Decrypts the contents of the passed encrypted RawByteString
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeString(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes; overload;

{$IFNDEF NEXTGEN}
    /// <summary>
    ///   Encrypts the contents of the passed Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeString(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes; overload;
    /// <summary>
    ///   Decrypts the contents of the passed encrypted Ansistring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeString(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes; overload;
    /// <summary>
    ///   Encrypts the contents of the passed Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to encrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Encoded will be the encrypted data, not the
    ///   source data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Encrypted string as a byte array
    /// </returns>
    function EncodeString(const Source: WideString; Format: TDECFormatClass = nil): TBytes; overload;
    /// <summary>
    ///   Decrypts the contents of the passed encrypted Widestring
    /// </summary>
    /// <param name="Source">
    ///   String to decrypt
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. One can pass a class reference of one of the
    ///   concrete data formatting classes here which will be internally used
    ///   to convert the data. Decoded will be the still encrypted data, not the
    ///   encrypted data. Formattings can be used to convert data into a format
    ///   suitable for the transport medium the data shall be transported with.
    /// </param>
    /// <returns>
    ///   Decrypted string as a byte array
    /// </returns>
    function DecodeString(const Source: WideString; Format: TDECFormatClass = nil): TBytes; overload;
{$ENDIF}
  end;

implementation

uses
  DECBaseClass;

function TDECFormattedCipher.EncodeBytes(const Source: TBytes): TBytes;
begin
  SetLength(Result, Length(Source));
  if Length(Result) > 0 then
    DoEncode(@Source[0], @Result[0], Length(Source));
end;

function TDECFormattedCipher.DecodeBytes(const Source: TBytes): TBytes;
begin
  SetLength(Result, Length(Source));
  if Length(Result) > 0 then
    DoDecode(@Source[0], @Result[0], Length(Source));
end;

procedure TDECFormattedCipher.DoEncodeDecodeStream(const Source, Dest: TStream; DataSize: Int64;
                                             const CipherProc: TDECCipherCodeEvent;
                                             const Progress: IDECProgress);
var
  Buffer: TBytes;
  BufferSize, Bytes: Integer;
  Min, Max, Pos: Int64;
begin
  Pos := Source.Position;
  if DataSize < 0 then
    DataSize := Source.Size - Pos;
  Min := Pos;
  Max := Pos + DataSize;
  if DataSize > 0 then
  try
    if StreamBufferSize <= 0 then
      StreamBufferSize := 8192;
    BufferSize := StreamBufferSize mod Context.BlockSize;
    if BufferSize = 0 then
      BufferSize := StreamBufferSize
    else
      BufferSize := StreamBufferSize + Context.BlockSize - BufferSize;
    if DataSize > BufferSize then
      SetLength(Buffer, BufferSize)
    else
      SetLength(Buffer, DataSize);
    while DataSize > 0 do
    begin
      if Assigned(Progress) then
        Progress.Process(Min, Max, Pos);
      Bytes := BufferSize;
      if Bytes > DataSize then
        Bytes := DataSize;
      Source.ReadBuffer(Buffer[0], Bytes);
      // The real encryption or decryption routine
      CipherProc(Buffer[0], Buffer[0], Bytes);
      Dest.WriteBuffer(Buffer[0], Bytes);
      Dec(DataSize, Bytes);
      Inc(Pos, Bytes);
    end;
  finally
    ProtectBytes(Buffer);
    if Assigned(Progress) then
      Progress.Process(Min, Max, Max);
  end;
end;

procedure TDECFormattedCipher.EncodeStream(const Source, Dest: TStream; DataSize: Int64;
                                           const Progress: IDECProgress);
begin
  DoEncodeDecodeStream(Source, Dest, DataSize,
                       Encode, Progress);
end;

procedure TDECFormattedCipher.DecodeStream(const Source, Dest: TStream; DataSize: Int64;
                                           const Progress: IDECProgress);
begin
  DoEncodeDecodeStream(Source, Dest, DataSize,
                       Decode, Progress);
end;

procedure TDECFormattedCipher.DoEncodeDecodeFile(const SourceFileName, DestFileName: string;
                                                 const Proc: TDECCipherCodeEvent;
                                                 const Progress: IDECProgress);
var
  S, D: TStream;
begin
  assert(SourceFileName <> DestFileName, 'Source and Dest file name may not be equal');

  S := TFileStream.Create(SourceFileName, fmOpenRead or fmShareDenyNone);
  try
    D := TFileStream.Create(DestFileName, fmCreate);
    try
      DoEncodeDecodeStream(S, D, S.Size, Proc, Progress);
    finally
      D.Free;
    end;
  finally
    S.Free;
  end;
end;

procedure TDECFormattedCipher.EncodeFile(const SourceFileName, DestFileName: string; const Progress: IDECProgress);
begin
  DoEncodeDecodeFile(SourceFileName, DestFileName, Encode, Progress);
end;

procedure TDECFormattedCipher.DecodeFile(const SourceFileName, DestFileName: string; const Progress: IDECProgress);
begin
  DoEncodeDecodeFile(SourceFileName, DestFileName, Decode, Progress);
end;

function TDECFormattedCipher.EncodeString(const Source: string; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
begin
  if Length(Source) > 0 then
  begin
    Len := Length(Source) * SizeOf(Source[low(Source)]);
    SetLength(Result, Len);
    Encode(Source[low(Source)], Result[0], Len);

    Result := ValidFormat(Format).Encode(System.SysUtils.BytesOf(Source));
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.EncodeString(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
begin
  if Length(Source) > 0 then
  begin
    Len := Length(Source) * SizeOf(Source[low(Source)]);
    SetLength(Result, Len);
    Encode(Source[low(Source)], Result[0], Len);

//    Result := ValidFormat(Format).Encode(Result);
    Result := ValidFormat(Format).Encode(System.SysUtils.BytesOf(Source));
//    Result := ValidFormat(Format).Encode(System.SysUtils.BytesOf(Source));
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.DecodeString(const Source: string; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(System.SysUtils.BytesOf(Source));

    Len := Length(Src);
    SetLength(Result, Len);
    Decode(Src[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.DecodeString(const Source: RawByteString; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(System.SysUtils.BytesOf(Source));

    Len := Length(Src);
    SetLength(Result, Len);
    Decode(Src[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.EncodeString(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
begin
  if Length(Source) > 0 then
  begin
    Len := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, Len);
    Encode(Source[1], Result[0], Len);

    Result := ValidFormat(Format).Encode(System.SysUtils.BytesOf(Source));
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.DecodeString(const Source: AnsiString; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(System.SysUtils.BytesOf(Source));

    Len := Length(Src);
    SetLength(Result, Len);
    Decode(Src[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.EncodeString(const Source: WideString; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
begin
  if Length(Source) > 0 then
  begin
    Len := Length(Source) * SizeOf(Source[1]);
    SetLength(Result, Len);
    Encode(Source[1], Result[0], Len);

    Result := ValidFormat(Format).Encode(System.SysUtils.BytesOf(Source));
  end
  else
    SetLength(Result, 0);
end;

function TDECFormattedCipher.DecodeString(const Source: WideString; Format: TDECFormatClass = nil): TBytes;
var
  Len: Integer;
  Src: TBytes;
begin
  if Length(Source) > 0 then
  begin
    Src := ValidFormat(Format).Decode(System.SysUtils.BytesOf(Source));

    Len := Length(Src);
    SetLength(Result, Len);
    Decode(Src[0], Result[0], Len);
  end
  else
    SetLength(Result, 0);
end;

end.
