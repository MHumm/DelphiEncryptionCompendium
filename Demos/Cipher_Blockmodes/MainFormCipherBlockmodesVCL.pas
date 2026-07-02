{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory of
  this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}

/// <summary>
///   Demo showing graphically why block modes for block ciphers are essential
///   and why ECB-mode should not be used
/// </summary>
unit MainFormCipherBlockmodesVCL;

interface

uses
  Winapi.Windows, Winapi.Messages, System.SysUtils, System.Variants, System.Classes,
  Vcl.Graphics, Vcl.Controls, Vcl.Forms, Vcl.Dialogs, Vcl.StdCtrls, Vcl.ExtCtrls,
  Vcl.ExtDlgs, DECCipherBase;

type
  /// <summary>
  ///   Structure for one single 24-bit pixel (Windows default is BGR)
  /// </summary>
  TRGBTriple = packed record
    rgbtBlue: Byte;
    rgbtGreen: Byte;
    rgbtRed: Byte;
  end;

  PRGBTripleArray = ^TRGBTripleArray;
  TRGBTripleArray = array[0..32767] of TRGBTriple;

  TByteArray = TArray<Byte>;

  TFormMain = class(TForm)
    OpenPictureDialog: TOpenPictureDialog;
    p_Main: TPanel;
    Splitter_Main: TSplitter;
    p_Left: TPanel;
    Label1: TLabel;
    i_Original: TImage;
    p_Right: TPanel;
    Label2: TLabel;
    i_Encrypted: TImage;
    p_Top: TPanel;
    Label3: TLabel;
    Label4: TLabel;
    b_LoadImage: TButton;
    b_EncryptImage: TButton;
    cb_Mode: TComboBox;
    tf_InitVector: TEdit;
    procedure b_EncryptImageClick(Sender: TObject);
    procedure b_LoadImageClick(Sender: TObject);
  private
    /// <summary>
    ///   Convert the contents of the bitmap into an array we can work with
    /// </summary>
    /// <param name="src">
    ///   Bitmap to convert
    /// </param>
    /// <param name="arr">
    ///   In this array the data will be stored.
    /// </param>
    procedure ScanlineToArray(src: TBitmap; var arr: TByteArray);
    /// <summary>
    ///   Creates a bitmap from the data of the passed array
    /// </summary>
    /// <param name="ByteArray">
    ///   Array with pixeldata which shall be transformed into a bitmap
    /// </param>
    /// <param name="Width">
    ///   Width in pixel the resulting bitmap shall have
    /// </param>
    /// <param name="Height">
    ///   Height in pixel the resulting bitmap shall have
    /// </param>
    /// <param name="Bitmap">
    ///   Bitmap into which the pixel data shall be written
    /// </param>
    procedure ByteArrayToBitmap(const ByteArray: TByteArray;
                                Width, Height: Integer;
                                var Bitmap: TBitmap);
    /// <summary>
    ///   Calculate the size of the target bitmap so that it is a multiple of
    ///   the blocksize of the cipher algorithm. If necessary further lines will
    ///   be added (height extension).
    /// </summary>
    /// <param name="SrcBitmap">
    ///   Bitmap from which the size for the target bitmap is being determined
    /// </param>
    /// <param name="BlockSize">
    ///   Block size in bytes. The resulting bitmap must be a multiple of that
    ///   in size
    /// </param>
    function CalculateBlockedBitmapSize(SrcBitmap: TBitmap;
                                        BlockSize: Integer): TPoint;
    /// <summary>
    ///   Encrypts the data of the passed bitmap
    /// </summary>
    /// <param name="SrcBitmap">
    ///   Bitmap to encrypt
    /// </param>
    /// <param name="Mode">
    ///   Block concatenation/chaining mode
    /// </param>
    /// <param name="IV">
    ///   Initialization vector
    /// </param>
    /// <returns>
    ///   Encrypted bitmap
    /// </returns>
    function DemoEncodeBitmap(SrcBitmap: TBitmap;
                              Mode: TCipherMode;
                              IV: RawByteString): TBitmap;
    /// <summary>
    ///   Returns the selected block chaining/concatenation mode
    /// </summary>
    function SelectedModeToEnum: TCipherMode;
  public
  end;

var
  FormMain: TFormMain;

implementation

uses
  System.Types,
  DecCiphers;

{$R *.dfm}

procedure TFormMain.b_EncryptImageClick(Sender: TObject);
var
  bmp : TBitmap;
begin
  bmp := DemoEncodeBitmap(i_Original.Picture.Bitmap,
                          SelectedModeToEnum,
                          RawByteString(tf_InitVector.Text));

  if assigned(bmp) then
  begin
    i_Encrypted.Picture.Bitmap.Assign(bmp);
    bmp.free;
  end;
end;

procedure TFormMain.b_LoadImageClick(Sender: TObject);
begin
  if OpenPictureDialog.Execute then
    i_Original.Picture.LoadFromFile(OpenPictureDialog.FileName);
end;

procedure TFormMain.ScanlineToArray(src:TBitmap; var arr:TByteArray);
var
  X, Y          : Integer;
  Line          : PRGBTripleArray;
  ByteIndex     : Integer;
  BytesPerPixel : Integer;
begin
  Assert(Assigned(src), 'No bitmap passed!');

  // In this example we assume 24-Bit format
  src.PixelFormat := pf24bit;
  BytesPerPixel   := SizeOf(TRGBTriple);

  // define arrow size: width * height * 3 byte (RGB)
  SetLength(arr, src.Width * src.Height * BytesPerPixel);

  ByteIndex := 0;

  for Y := 0 to src.Height - 1 do
  begin
    // Fetch pointer to the beginning of the scanline
    Line := src.ScanLine[Y];

    for X := 0 to src.Width - 1 do
    begin
      // Read nout values from the bitmap and write them into the array
      arr[ByteIndex]     := Line[X].rgbtRed;   // R
      arr[ByteIndex + 1] := Line[X].rgbtGreen; // G
      arr[ByteIndex + 2] := Line[X].rgbtBlue;  // B

      Inc(ByteIndex, BytesPerPixel);
    end;
  end;
end;

function TFormMain.CalculateBlockedBitmapSize(SrcBitmap: TBitmap; BlockSize: Integer): TPoint;
var
  SrcBytes      : Int64;    // Size of the source bitmap in bytes based on byte per pixel
  PixelByteSize : Byte;     // Bytes for one pixel according to pixel format (here: RGB)
  ScM,                      // smallest common multiple of PixelByteSize and BlockSize
  PxBlockCount  : Integer;
  ModuloResult  : Integer;
  LineSizeBytes : Integer;  // Number of bytes one bitmap line occupies
  Height        : Integer;
begin
  Assert(Assigned(SrcBitmap), 'No bitmap passed!');

  // Pixel format pf24Bit = 3 byte per pixel
  PixelByteSize := 3;
  ScM := BlockSize * PixelByteSize; // Smallest common multiple of block size
                                    // and 1 pixel — i.e., how many bytes we need
                                    // so that all bytes of the pixels can be
                                    // accommodated.
                                    // With a block size of 16 and 3 bytes per pixel,
                                    // you need 3 blocks = 48 bytes so that no pixel’s
                                    // bytes “stick out” and all blocks are completely
                                    // filled with whole pixels.

  // size of the source bitmap in byte
  SrcBytes := (SrcBitmap.Width * SrcBitmap.Height) * PixelByteSize;

  // How many complete pixel blocks fit into the bitmap (in bytes)
  PxBlockCount := (SrcBytes Div ScM);

  // By how much do you need to increase the number of blocks until you have at
  // least the number of bytes required by the bitmap?
  ModuloResult := (SrcBytes MOD (ScM * PxBlockCount));

  // If it doesn't exactly fit?
  if (ModuloResult <> 0) then
  begin
    // Number of bytes one line of the bitmap needs
    LineSizeBytes := SrcBitmap.Width * PixelByteSize;

    Height := SrcBitmap.Height;

    // add further lines until we have a multiple of the pixel block size bytes
    repeat
      inc(Height);
      inc(SrcBytes, LineSizeBytes);
    until ((SrcBytes mod ScM) = 0);
  end
  else
    Height := SrcBitmap.Height;

  Result.X := SrcBitmap.Width;
  Result.Y := Height;
end;

procedure TFormMain.ByteArrayToBitmap(const ByteArray: TByteArray;
                                      Width, Height: Integer;
                                      var Bitmap: TBitmap);
var
  X, Y          : Integer;
  Line          : PRGBTripleArray;
  ByteIndex     : Integer;
  BytesPerPixel : Integer;
begin
  Assert(Assigned(ByteArray), 'No initialized source array passed!');
  Assert(Assigned(Bitmap),    'No bitmap passed!');

  // initialize image dimensions and format
  Bitmap.PixelFormat := pf24bit;
  Bitmap.Width       := Width;
  Bitmap.Height      := Height;

  BytesPerPixel := SizeOf(TRGBTriple);
  ByteIndex     := 0;

  // Safety check: Are the bytes in the array sufficient for this image size?
  if Length(ByteArray) < (Width * Height * BytesPerPixel) then
    raise Exception.Create('Failure: the byte array is too small for the image dimensions given.');

  for Y := 0 to Height - 1 do
  begin
    // Get a pointer to the target line of the bitmap
    Line := Bitmap.ScanLine[Y];

    for X := 0 to Width - 1 do
    begin
      // Read values from the byte array and write those into the scanline
      Line[X].rgbtRed   := ByteArray[ByteIndex];     // R
      Line[X].rgbtGreen := ByteArray[ByteIndex + 1]; // G
      Line[X].rgbtBlue  := ByteArray[ByteIndex + 2]; // B

      Inc(ByteIndex, BytesPerPixel);
    end;
  end;
end;

function TFormMain.SelectedModeToEnum: TCipherMode;
begin
  Result := cmECBx;

  case cb_Mode.ItemIndex of
    0 : Result := cmECBx;
    1 : Result := cmCBCx;
    2 : Result := cmCTSx;
    3 : Result := cmCFB8;
    4 : Result := cmCFBx;
    5 : Result := cmOFB8;
    6 : Result := cmOFBx;
    7 : Result := cmCFS8;
    8 : Result := cmCFSx;
  end;
end;

function TFormMain.DemoEncodeBitmap(SrcBitmap:TBitmap;
                                    Mode: TCipherMode;
                                    IV: RawByteString):TBitmap;
var
  DstSize   : TPoint;
  Cipher    : TCipher_AES128;
  SrcBytes,
  DstBytes  : TByteArray;
  SrcHeight : Integer;
begin
  Cipher := TCipher_AES128.Create;
  try
    Cipher.init(RawByteString('PascalSalamanca!'), IV, 32);
    Cipher.Mode := Mode;

    SrcHeight := SrcBitmap.Height;
    DstSize := CalculateBlockedBitmapSize(SrcBitmap, Cipher.Context.BlockSize);

    // is the new calculated height bigger than the original one?
    if (DstSize.Y > SrcHeight) then
      // Enlarge bitmap
      SrcBitmap.Height := DstSize.Y;

    ScanlineToArray(SrcBitmap, SrcBytes);

    DstBytes := Cipher.EncodeBytes(SrcBytes);
  finally
    Cipher.Free;
  end;
  Result := TBitmap.Create;
  ByteArrayToBitmap(DstBytes, DstSize.x, DstSize.y, Result);
end;

end.
