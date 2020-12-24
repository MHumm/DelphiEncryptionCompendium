{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License. A copy of this licence is found in the root directory
  of this project in the file LICENCE.txt or alternatively at

    http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing,
  software distributed under the License is distributed on an
  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  KIND, either express or implied.  See the License for the
  specific language governing permissions and limitations
  under the License.
*****************************************************************************}
unit DECCiphers;

interface

uses
  {$IFDEF FPC}
  SysUtils,
  {$ELSE}
  System.SysUtils,
  {$ENDIF}
  DECCipherBase, DECCipherFormats, DECUtil, DECTypes, DECData, DECDataCipher;

{$INCLUDE DECOptions.inc}

type
  // Cipher Classes

  /// <summary>
  ///   Null cipher, doesn't encrypt, only copy
  /// </summary>
  TCipher_Null          = class;
  /// <summary>
  ///   A block based encryption algorithm with 32 to 448 bit key length
  /// </summary>
  TCipher_Blowfish      = class;
  /// <summary>
  ///   AES Round 2 Final Candidate
  /// </summary>
  TCipher_Twofish       = class;
  /// <summary>
  ///   International Data Encryption Algorithm, formerly patentet,
  ///   now patent free
  /// </summary>
  TCipher_IDEA          = class;
  /// <summary>
  ///   Carlisle Adams and Stafford Tavares, 256 bit key length
  /// </summary>
  TCipher_Cast256       = class;
  /// <summary>
  ///   AES Round 2 Final Candidate
  /// </summary>
  TCipher_Mars          = class;
  /// <summary>
  ///   Streamcipher in as Block Cipher
  /// </summary>
  TCipher_RC4           = class;
  /// <summary>
  ///   AES Round 2 Final Candidate
  /// </summary>
  TCipher_RC6           = class;
  /// <summary>
  ///   AES Round 2 Final Candidate
  /// </summary>
  TCipher_Rijndael      = class;
  /// <summary>
  ///   AES winner = TCipher_Rijndael
  /// </summary>
  TCipher_AES           = class;
  /// <summary>
  ///   A block cipher invented by Joan Daemen and Vincent Rijmen. The design,
  ///   published in 1997, is a forerunner to Rijndael, which has been adopted
  ///   as the Advanced Encryption Standard. Square was introduced together with
  ///   a new form of cryptanalysis discovered by Lars Knudsen, called the
  ///   "Square attack".
  ///   The structure of Square is a substitution-permutation network with eight
  ///   rounds, operating on 128-bit blocks and using a 128-bit key.
  /// </summary>
  /// <remarks>
  ///   If possible use TCipher_AES instead
  /// </remarks>
  TCipher_Square        = class;
  /// <summary>
  ///   Stream Cipher in Blockmode (on UInt32), very fast
  /// </summary>
  TCipher_SCOP          = class;
  /// <summary>
  ///   Stream Cipher, eq. Design from german ENIGMA Machine
  /// </summary>
  TCipher_Sapphire      = class;
  /// <summary>
  ///   Single DES  8 byte Blocksize,  8 byte Keysize,  56 bits relevant
  /// </summary>
  TCipher_1DES          = class;
  /// <summary>
  ///   Double DES  8 byte Blocksize, 16 byte Keysize, 112 bits relevant
  /// </summary>
  TCipher_2DES          = class;
  /// <summary>
  ///   Triple DES  8 byte Blocksize, 24 byte Keysize, 168 bits relevant
  /// </summary>
  TCipher_3DES          = class;
  /// <summary>
  ///   Triple DES 16 byte Blocksize, 16 byte Keysize, 112 bits relevant
  /// </summary>
  TCipher_2DDES         = class;
  /// <summary>
  ///   Triple DES 16 byte Blocksize, 24 byte Keysize, 168 bits relevant
  /// </summary>
  TCipher_3DDES         = class;
  /// <summary>
  ///   Triple DES 24 byte Blocksize, 24 byte Keysize, 168 bits relevant
  /// </summary>
  TCipher_3TDES         = class;
  /// <summary>
  ///   A 1994 developed block cipher using a 96 bit key. 3-Way, is vulnerable
  ///   to related key cryptanalysis.
  /// </summary>
  TCipher_3Way          = class;
  /// <summary>
  ///   Carlisle Adams and Stafford Tavares, 128 bit key length
  /// </summary>
  TCipher_Cast128       = class;
  /// <summary>
  ///   Russian Cipher
  /// </summary>
  TCipher_Gost          = class;
  /// <summary>
  ///   Alias/new name for Gost cipher
  /// </summary>
  TCipher_Magma         = class;
  /// <summary>
  ///   Misty1 is a block cipher developed 1995 by Mitsubishi. It is free only for
  ///   academical and non-profit works in RFC 2994. it is otherwise patented.
  ///   In 2015 it got broken via integral cryptoanalysis.
  /// </summary>
  TCipher_Misty         = class;
  /// <summary>
  ///   A 1996 block cipher with a key length of 120 bit. It can be broken with
  ///   a relatively low number of ciphertext/plaintext queries.
  /// </summary>
  TCipher_NewDES        = class;
  /// <summary>
  ///   Camelia, a 128 bit block cipher.
  ///   Specification: https://info.isl.ntt.co.jp/crypt/eng/camellia/dl/01espec.pdf
  /// </summary>
  TCipher_Q128          = class;
  /// <summary>
  ///   Rivest Cipher 2, a 1987 developed cipher with a default keysize of 64 bit
  /// </summary>
  TCipher_RC2           = class;
  /// <summary>
  ///   Rivest Cipher 5, a 1994 developed cipher with emphasis on speed and low
  ///   size in order to make it efficient on embedded hardware as well. Key sizes
  ///   of up to 2048 bits are possible but 128 bits are suggested. The algorithm
  ///   was patented in the US up to 2015.
  /// </summary>
  TCipher_RC5           = class;
  /// <summary>
  ///   SAFER = Secure And Fast Encryption Routine
  /// </summary>
  TCipher_SAFER         = class;
  /// <summary>
  ///   A 1996 published block cipher with a key size of 128 bits. It was
  ///   identified as one of the predecessors of Rijndael
  /// </summary>
  TCipher_Shark         = class;
  /// <summary>
  ///   A NSA developed and 1998 published block cipher with a key length of
  ///   80 bit. Soon after publication various weaknesses have been identified.
  /// </summary>
  TCipher_Skipjack      = class;
  /// <summary>
  ///   Tiny Encryption Algorithm
  /// </summary>
  TCipher_TEA           = class;
  /// <summary>
  ///   Tiny Encryption Algorithm, 1st extended Version
  /// </summary>
  TCipher_XTEA          = class;
  /// <summary>
  ///   = TCipher_XTEA (kept for backward compatibility)
  /// </summary>
  TCipher_TEAN          = class;

  // Definitions needed for Skipjack algorithm
  PSkipjackTab = ^TSkipjackTab;
  TSkipjackTab = array[0..255] of Byte;

  /// <summary>
  ///   A do nothing cipher, usefull for debugging and development purposes. Do
  ///   not use it for actual encryption as it will not encrypt anything at all!
  /// </summary>
  TCipher_Null = class(TDECFormattedCipher)
  protected
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    /// <summary>
    ///   Provides meta data about the cipher algorithm used like key size.
    /// </summary>
    class function Context: TCipherContext; override;
  end;

  TCipher_Blowfish = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Twofish = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_IDEA = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Cast256 = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Mars = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  /// <summary>
  ///   This is a well known stream cipher. In February 2015 its use in context
  ///   of TLS has been forbidden due to severe security issues.
  /// </summary>
  TCipher_RC4 = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_RC6 = class(TDECFormattedCipher)
  private
    FRounds: Integer;
    procedure SetRounds(Value: Integer);
    /// <summary>
    ///   Limits the number of rounds used to a minimum or maximum value,
    ///   depending on the current value. If FRounds is 0 it will be set to 20.
    /// </summary>
    procedure LimitRounds; inline;
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
    /// <summary>
    ///   Sets the number of rounds/times the algorithm is being applied to the
    ///   data. Range should be 16-24 and default is 20 rounds.
    /// </summary>
    property Rounds: Integer read FRounds write SetRounds;
  end;

  TCipher_Rijndael = class(TDECFormattedCipher)
  private
    FRounds: Integer;
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
    /// <summary>
    ///   Gets the number of rounds/times the algorithm is being applied to the
    ///   data. The number of rounds depends on the key size.
    /// </summary>
    property Rounds: Integer read FRounds;
  end;

  TCipher_AES = class(TCipher_Rijndael);

  TCipher_Square = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_SCOP = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Sapphire = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_1DES = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Data">
    ///   Key for the current block to be encrypted/decrypted?
    /// </param>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    /// <param name="Reverse">
    ///   Defines whether some internal calculation needs to be based from the
    ///   start index or the highest index  (= reverse)
    /// </param>
    procedure DoInitKey(const Data: array of Byte; Key: PUInt32Array; Reverse: Boolean);
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_2DES = class(TCipher_1DES)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_3DES = class(TCipher_1DES)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_2DDES = class(TCipher_2DES)
  protected
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_3DDES = class(TCipher_3DES)
  protected
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_3TDES = class(TCipher_3DES)
  protected
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_3Way = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Cast128 = class(TDECFormattedCipher)
  private
    FRounds: Integer;
    procedure SetRounds(Value: Integer);
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;

    /// <summary>
    ///   Sets the number of rounds/times the algorithm is being applied to the
    ///   data. Default value is 16 rounds.
    /// </summary>
    property Rounds: Integer read FRounds write SetRounds;
  end;

  TCipher_Gost = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  /// <summary>
  ///   Alias for Gost
  /// </summary>
  TCipher_Magma = class(TCipher_Gost);

  /// <summary>
  ///   Do no longer use this algorithm if possible, as it got broken in 2015
  ///   by crypto analysis.
  /// </summary>
  TCipher_Misty = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  /// <summary>
  ///   While this algorithm resembles the Data Encryption Standard (DES),
  ///   it is easier to implement in software and is supposed to be more secure.
  ///   It is not to be confused with another algorithm - known by the same
  ///   name - which is simply DES without the initial and final permutations.
  ///   The NewDES here is a completely different algorithm.
  ///
  ///   Be aware though that recent crypto analysis shows that this algorithm is
  ///   less safe than DES and thus not to be recommended for use!
  /// </summary>
  TCipher_NewDES = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Q128 = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_RC2 = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_RC5 = class(TDECFormattedCipher)
  private
    FRounds: Integer;
    procedure SetRounds(Value: Integer);
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;

    /// <summary>
    ///   Sets the number of rounds/times the algorithm is being applied to the
    ///   data. Range should be 8-16 and default is 12 rounds.
    /// </summary>
    property Rounds: Integer read FRounds write SetRounds;
  end;

  /// <summary>
  ///  svK40     SAFER K-40    Keysize is 40bit  ->  5 Byte
  ///  svK64     SAFER K-64    Keysize is 64bit  ->  8 Byte
  ///  svK128    SAFER K-128   KeySize is 128bit -> 16 Byte
  ///  svSK40    SAFER SK-40   Stronger Version from K-40 with better Key Scheduling
  ///  svSK64    SAFER SK-64   Stronger Version from K-64 with better Key Scheduling
  ///  svSK128   SAFER SK-128  Stronger Version from K-128 with better Key Scheduling
  /// </summary>
  TSAFERVersion = (svSK128, svSK64, svSK40, svK128, svK64, svK40);

  TCipher_SAFER = class(TDECFormattedCipher)
  private
    FRounds: Integer;
    FVersion: TSAFERVersion;
    procedure SetRounds(Value: Integer);
    procedure SetVersion(Value: TSAFERVersion);
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;

    /// <summary>
    ///   Sets the number of rounds/times the algorithm is being applied to the
    ///   data. Range should be 4-13 and default is 5, 6, 10 or 8 rounds
    ///   depending on the version
    /// </summary>
    property Rounds: Integer read FRounds write SetRounds;
    property Version: TSAFERVersion read FVersion write SetVersion;
  end;

  TCipher_Shark = class(TDECFormattedCipher)
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_Skipjack = class(TDECFormattedCipher)
  strict private
    procedure SkipjackIncCheck(var ATab: PSkipjackTab; AMin: PSkipjackTab; AMax: PByte); inline;
    procedure SkipjackDecCheck(var ATab: PSkipjackTab; AMin: PByte; AMax: PSkipjackTab); inline;
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;
  end;

  TCipher_TEA = class(TDECFormattedCipher)
  private
    FRounds: Integer;
    procedure SetRounds(Value: Integer);
  protected
    /// <summary>
    ///   Initialize the key, based on the key passed in
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); override;
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  public
    class function Context: TCipherContext; override;

    /// <summary>
    ///   16 - 256 Rounds, 16 (default) is sufficient, 64 is the official
    ///   recommendation. If a value outside the range of 16 to 256 is assigned
    ///   it will be limited to that range.
    /// </summary>
    property Rounds: Integer read FRounds write SetRounds;
  end;

  /// <summary>
  ///   XTEA is an improved version of the TEA algorithm.
  /// </summary>
  /// <remarks>
  ///   In DEC V5.2 at least and in former commits of DEC 6.0 development version
  ///   this algorithm was broken due to differences in brackets and thus returned
  ///   a different result. It is unclear why nobody reported this as bug yet
  ///   but be aware that if you need the old variant for compatibility reasons
  ///   you need a commit from before 3rd December 2020.
  /// </remarks>
  TCipher_XTEA = class(TCipher_TEA)
  protected
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); override;
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); override;
  end;

  TCipher_TEAN = class(TCipher_XTEA);

implementation

{$IFOPT Q+}{$DEFINE RESTORE_OVERFLOWCHECKS}{$Q-}{$ENDIF}
{$IFOPT R+}{$DEFINE RESTORE_RANGECHECKS}{$R-}{$ENDIF}

{ TCipher_Null }

class function TCipher_Null.Context: TCipherContext;
begin
  Result.KeySize                     := 0;
  Result.BlockSize                   := 1;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 0;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctNull, ctSymmetric];
end;

procedure TCipher_Null.DoInit(const Key; Size: Integer);
begin
  // dummy
end;

procedure TCipher_Null.DoEncode(Source, Dest: Pointer; Size: Integer);
begin
  if Source <> Dest then
    Move(Source^, Dest^, Size);
end;

procedure TCipher_Null.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  if Source <> Dest then
    Move(Source^, Dest^, Size);
end;

{ TCipher_Blowfish }

type
  PBlowfish = ^TBlowfish;
  TBlowfish = array[0..3, 0..255] of UInt32;

class function TCipher_Blowfish.Context: TCipherContext;
begin
  Result.KeySize                     := 56;
  Result.BufferSize                  := 8;
  Result.BlockSize                   := 8;
  Result.AdditionalBufferSize        := SizeOf(Blowfish_Data) + SizeOf(Blowfish_Key);
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType := [ctSymmetric, ctBlock];
end;

procedure TCipher_Blowfish.DoInit(const Key; Size: Integer);
var
  I, J: Integer;
  B: array[0..1] of UInt32;
  K: PByteArray;
  P: PUInt32Array;
  S: PBlowfish;
begin
  K := @Key;
  S := FAdditionalBuffer;
  P := Pointer(PByte(FAdditionalBuffer) + SizeOf(Blowfish_Data)); // for Pointer Math

  Move(Blowfish_Data, S^, SizeOf(Blowfish_Data));
  Move(Blowfish_Key, P^, Sizeof(Blowfish_Key));
  J := 0;
  if Size > 0 then
    for I := 0 to 17 do
    begin
      P[I] := P[I] xor (K[(J + 0) mod Size] shl 24 +
                        K[(J + 1) mod Size] shl 16 +
                        K[(J + 2) mod Size] shl  8 +
                        K[(J + 3) mod Size] shl  0);
      J := (J + 4) mod Size;
    end;
  FillChar(B, SizeOf(B), 0);

  for I := 0 to 8 do
  begin
    DoEncode(@B, @B, SizeOf(B));
    P[I * 2 + 0] := SwapUInt32(B[0]);
    P[I * 2 + 1] := SwapUInt32(B[1]);
  end;
  for I := 0 to 3 do
    for J := 0 to 127 do
    begin
      DoEncode(@B, @B, SizeOf(B));
      S[I, J * 2 + 0] := SwapUInt32(B[0]);
      S[I, J * 2 + 1] := SwapUInt32(B[1]);
    end;
  FillChar(B, SizeOf(B), 0);
end;

procedure TCipher_Blowfish.DoEncode(Source, Dest: Pointer; Size: Integer);
{$IFDEF X86ASM}
// Source = EDX, Dest = ECX, Size on Stack
asm
        PUSH   EDI
        PUSH   ESI
        PUSH   EBX
        PUSH   EBP
        PUSH   ECX
        MOV    ESI,[EAX].TCipher_Blowfish.FAdditionalBuffer
        MOV    EBX,[EDX + 0]     // A
        MOV    EBP,[EDX + 4]     // B
        BSWAP  EBX               // CPU >= 486
        BSWAP  EBP
        XOR    EBX,[ESI + 4 * 256 * 4]
        XOR    EDI,EDI
@@1:    MOV    EAX,EBX
        SHR    EBX,16
        MOVZX  ECX,BH
        AND    EBX,0FFh
        MOV    ECX,[ESI + ECX * 4 + 1024 * 0]
        MOV    EBX,[ESI + EBX * 4 + 1024 * 1]
        MOVZX  EDX,AH
        ADD    EBX,ECX
        MOVZX  ECX,AL
        MOV    EDX,[ESI + EDX * 4 + 1024 * 2]
        MOV    ECX,[ESI + ECX * 4 + 1024 * 3]
        XOR    EBX,EDX
        XOR    EBP,[ESI + 4 * 256 * 4 + 4 + EDI * 4]
        ADD    EBX,ECX
        INC    EDI
        XOR    EBX,EBP
        TEST   EDI,010h
        MOV    EBP,EAX
        JZ     @@1
        POP    EAX
        XOR    EBP,[ESI + 4 * 256 * 4 + 17 * 4]
        BSWAP  EBX
        BSWAP  EBP
        MOV    [EAX + 4],EBX
        MOV    [EAX + 0],EBP
        POP    EBP
        POP    EBX
        POP    ESI
        POP    EDI
end;
{$ELSE !X86ASM}
var
  I, A, B: UInt32;
  P: PUInt32Array;
  D: PBlowfish;
begin
  Assert(Size = Context.BlockSize, 'Size of ' + IntToStr(Size) + ' does not equal '+
                                   'block size of ' + IntToStr(Context.BlockSize));

  D := Pointer(FBuffer);
  P := Pointer(PByte(FBuffer) + SizeOf(Blowfish_Data)); // for Pointer Math
  A := SwapUInt32(PUInt32Array(Source)[0]) xor P[0]; P := @P[1];
  B := SwapUInt32(PUInt32Array(Source)[1]);
  for I := 0 to 7 do
  begin
    B := B xor P[0] xor (D[0, A shr 24        ] +
                         D[1, A shr 16 and $FF] xor
                         D[2, A shr  8 and $FF] +
                         D[3, A        and $FF]);

    A := A xor P[1] xor (D[0, B shr 24        ] +
                         D[1, B shr 16 and $FF] xor
                         D[2, B shr  8 and $FF] +
                         D[3, B        and $FF]);
    P := @P[2];
  end;
  PUInt32Array(Dest)[0] := SwapUInt32(B xor P[0]);
  PUInt32Array(Dest)[1] := SwapUInt32(A);
end;
{$ENDIF !X86ASM}

procedure TCipher_Blowfish.DoDecode(Source, Dest: Pointer; Size: Integer);
{$IFDEF X86ASM}
asm
        PUSH   EDI
        PUSH   ESI
        PUSH   EBX
        PUSH   EBP
        PUSH   ECX
        MOV    ESI,[EAX].TCipher_Blowfish.FAdditionalBuffer
        MOV    EBX,[EDX + 0]     // A
        MOV    EBP,[EDX + 4]     // B
        BSWAP  EBX
        BSWAP  EBP
        XOR    EBX,[ESI + 4 * 256 * 4 + 17 * 4]
        MOV    EDI,16
@@1:    MOV    EAX,EBX
        SHR    EBX,16
        MOVZX  ECX,BH
        MOVZX  EDX,BL
        MOV    EBX,[ESI + ECX * 4 + 1024 * 0]
        MOV    EDX,[ESI + EDX * 4 + 1024 * 1]
        MOVZX  ECX,AH
        LEA    EBX,[EBX + EDX]
        MOVZX  EDX,AL
        MOV    ECX,[ESI + ECX * 4 + 1024 * 2]
        MOV    EDX,[ESI + EDX * 4 + 1024 * 3]
        XOR    EBX,ECX
        XOR    EBP,[ESI + 4 * 256 * 4 + EDI * 4]
        LEA    EBX,[EBX + EDX]
        XOR    EBX,EBP
        DEC    EDI
        MOV    EBP,EAX
        JNZ    @@1
        POP    EAX
        XOR    EBP,[ESI + 4 * 256 * 4]
        BSWAP  EBX
        BSWAP  EBP
        MOV    [EAX + 0],EBP
        MOV    [EAX + 4],EBX
        POP    EBP
        POP    EBX
        POP    ESI
        POP    EDI
end;
{$ELSE !X86ASM}
var
  I, A, B: UInt32;
  P: PUInt32Array;
  D: PBlowfish;
begin
  Assert(Size = Context.BlockSize);

  D := Pointer(FBuffer);
  P := Pointer(PByte(FBuffer) + SizeOf(Blowfish_Data) + SizeOf(Blowfish_Key) - SizeOf(Int32));
  A := SwapUInt32(PUInt32Array(Source)[0]) xor P[0];
  B := SwapUInt32(PUInt32Array(Source)[1]);
  for I := 0 to 7 do
  begin
    Dec(PUInt32(P), 2);
    B := B xor P[1] xor (D[0, A shr 24        ] +
                         D[1, A shr 16 and $FF] xor
                         D[2, A shr  8 and $FF] +
                         D[3, A        and $FF]);
    A := A xor P[0] xor (D[0, B shr 24        ] +
                         D[1, B shr 16 and $FF] xor
                         D[2, B shr  8 and $FF] +
                         D[3, B        and $FF]);
  end;
  Dec(PUInt32(P));
  PUInt32Array(Dest)[0] := SwapUInt32(B xor P[0]);
  PUInt32Array(Dest)[1] := SwapUInt32(A);
end;
{$ENDIF !X86ASM}

{ TCipher_Twofish }

type
  PTwofishBox = ^TTwofishBox;
  TTwofishBox = array[0..3, 0..255] of UInt32;

  TLongRec = record
    case Integer of
      0: (L: UInt32);
      1: (A, B, C, D: Byte);
    end;

class function TCipher_Twofish.Context: TCipherContext;
begin
  Result.KeySize                     := 32;
  Result.BufferSize                  := 16;
  Result.BlockSize                   := 16;
  Result.AdditionalBufferSize        := 4256;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Twofish.DoInit(const Key; Size: Integer);
var
  BoxKey: array[0..3] of TLongRec;
  SubKey: PUInt32Array;
  Box: PTwofishBox;

  procedure SetupKey;

    function Encode(K0, K1: Integer): Integer;
    var
      R, I, J, G2, G3: Integer;
      B: byte;
    begin
      R := 0;
      for I := 0 to 1 do
      begin
        if I <> 0 then
          R := R xor K0
        else
          R := R xor K1;
        for J := 0 to 3 do
        begin
          B := R shr 24;
          if B and $80 <> 0 then
            G2 := (B shl 1 xor $014D) and $FF
          else
            G2 := B shl 1 and $FF;
          if B and 1 <> 0 then
            G3 := (B shr 1 and $7F) xor $014D shr 1 xor G2
          else
            G3 := (B shr 1 and $7F) xor G2;
          R := R shl 8 xor G3 shl 24 xor G2 shl 16 xor G3 shl 8 xor B;
        end;
      end;
      Result := R;
    end;

    function F32(X: Integer; K: array of Integer): Integer;
    var
      A, B, C, D: UInt32;
    begin
      A := X        and $FF;
      B := X shr  8 and $FF;
      C := X shr 16 and $FF;
      D := X shr 24;
      if Size = 32 then
      begin
        A := Twofish_8x8[1, A] xor K[3]        and $FF;
        B := Twofish_8x8[0, B] xor K[3] shr  8 and $FF;
        C := Twofish_8x8[0, C] xor K[3] shr 16 and $FF;
        D := Twofish_8x8[1, D] xor K[3] shr 24;
      end;
      if Size >= 24 then
      begin
        A := Twofish_8x8[1, A] xor K[2]        and $FF;
        B := Twofish_8x8[1, B] xor K[2] shr  8 and $FF;
        C := Twofish_8x8[0, C] xor K[2] shr 16 and $FF;
        D := Twofish_8x8[0, D] xor K[2] shr 24;
      end;
      A := Twofish_8x8[0, A] xor K[1]        and $FF;
      B := Twofish_8x8[1, B] xor K[1] shr  8 and $FF;
      C := Twofish_8x8[0, C] xor K[1] shr 16 and $FF;
      D := Twofish_8x8[1, D] xor K[1] shr 24;

      A := Twofish_8x8[0, A] xor K[0]        and $FF;
      B := Twofish_8x8[0, B] xor K[0] shr  8 and $FF;
      C := Twofish_8x8[1, C] xor K[0] shr 16 and $FF;
      D := Twofish_8x8[1, D] xor K[0] shr 24;

      Result := Twofish_Data[0, A] xor Twofish_Data[1, B] xor
                Twofish_Data[2, C] xor Twofish_Data[3, D];
    end;

  var
    I, J, A, B: Integer;
    E, O: array[0..3] of Integer;
    K: array[0..7] of Integer;
  begin
    FillChar(K, SizeOf(K), 0);
    Move(Key, K, Size);
    if Size <= 16 then
      Size := 16
    else
    if Size <= 24 then
      Size := 24
    else
      Size := 32;
    J := Size shr 3 - 1;
    for I := 0 to J do
    begin
      E[I] := K[I shl 1];
      O[I] := K[I shl 1 + 1];
      BoxKey[J].L := Encode(E[I], O[I]);
      Dec(J);
    end;
    J := 0;
    for I := 0 to 19 do
    begin
      A := F32(J, E);
      B := F32(J + $01010101, O);
      B := B shl 8 or B shr 24;
      SubKey[I shl 1] := A + B;
      B := A + B shl 1;     // here buggy instead shr 1 it's correct shl 1
      SubKey[I shl 1 + 1] := B shl 9 or B shr 23;
      Inc(J, $02020202);
    end;
  end;

  procedure DoXOR(D, S: PUInt32Array; Value: UInt32);
  var
    I: UInt32;
  begin
    Value := (Value and $FF) * $01010101;
    for I := 0 to 63 do
      D[I] := S[I] xor Value;
  end;

  procedure SetupBox128;
  var
    L: array[0..255] of Byte;
    A, I: Integer;
  begin
    DoXOR(@L, @Twofish_8x8[0], BoxKey[1].L);
    A := BoxKey[0].A;
    for I := 0 to 255 do
      Box[0, I] := Twofish_Data[0, Twofish_8x8[0, L[I]] xor A];
    DoXOR(@L, @Twofish_8x8[1], BoxKey[1].L shr 8);
    A := BoxKey[0].B;
    for I := 0 to 255 do
      Box[1, I] := Twofish_Data[1, Twofish_8x8[0, L[I]] xor A];
    DoXOR(@L, @Twofish_8x8[0], BoxKey[1].L shr 16);
    A := BoxKey[0].C;
    for I := 0 to 255 do
      Box[2, I] := Twofish_Data[2, Twofish_8x8[1, L[I]] xor A];
    DoXOR(@L, @Twofish_8x8[1], BoxKey[1].L shr 24);
    A := BoxKey[0].D;
    for I := 0 to 255 do
      Box[3, I] := Twofish_Data[3, Twofish_8x8[1, L[I]] xor A];
  end;

  procedure SetupBox192;
  var
    L: array[0..255] of Byte;
    A, B, I: Integer;
  begin
    DoXOR(@L, @Twofish_8x8[1], BoxKey[2].L);
    A := BoxKey[0].A;
    B := BoxKey[1].A;
    for I := 0 to 255 do
      Box[0, I] := Twofish_Data[0, Twofish_8x8[0, Twofish_8x8[0, L[I]] xor B] xor A];
    DoXOR(@L, @Twofish_8x8[1], BoxKey[2].L shr 8);
    A := BoxKey[0].B;
    B := BoxKey[1].B;
    for I := 0 to 255 do
      Box[1, I] := Twofish_Data[1, Twofish_8x8[0, Twofish_8x8[1, L[I]] xor B] xor A];
    DoXOR(@L, @Twofish_8x8[0], BoxKey[2].L shr 16);
    A := BoxKey[0].C;
    B := BoxKey[1].C;
    for I := 0 to 255 do
      Box[2, I] := Twofish_Data[2, Twofish_8x8[1, Twofish_8x8[0, L[I]] xor B] xor A];
    DoXOR(@L ,@Twofish_8x8[0], BoxKey[2].L shr 24);
    A := BoxKey[0].D;
    B := BoxKey[1].D;
    for I := 0 to 255 do
      Box[3, I] := Twofish_Data[3, Twofish_8x8[1, Twofish_8x8[1, L[I]] xor B] xor A];
  end;

  procedure SetupBox256;
  var
    L: array[0..255] of Byte;
    K: array[0..255] of Byte;
    A, B, I: Integer;
  begin
    DoXOR(@K, @Twofish_8x8[1], BoxKey[3].L);
    for I := 0 to 255 do
      L[I] := Twofish_8x8[1, K[I]];
    DoXOR(@L, @L, BoxKey[2].L);
    A := BoxKey[0].A;
    B := BoxKey[1].A;
    for I := 0 to 255 do
      Box[0, I] := Twofish_Data[0, Twofish_8x8[0, Twofish_8x8[0, L[I]] xor B] xor A];
    DoXOR(@K, @Twofish_8x8[0], BoxKey[3].L shr 8);
    for I := 0 to 255 do
      L[I] := Twofish_8x8[1, K[I]];
    DoXOR(@L, @L, BoxKey[2].L shr 8);
    A := BoxKey[0].B;
    B := BoxKey[1].B;
    for I := 0 to 255 do
      Box[1, I] := Twofish_Data[1, Twofish_8x8[0, Twofish_8x8[1, L[I]] xor B] xor A];
    DoXOR(@K, @Twofish_8x8[0], BoxKey[3].L shr 16);
    for I := 0 to 255 do
      L[I] := Twofish_8x8[0, K[I]];
    DoXOR(@L, @L, BoxKey[2].L shr 16);
    A := BoxKey[0].C;
    B := BoxKey[1].C;
    for I := 0 to 255 do
      Box[2, I] := Twofish_Data[2, Twofish_8x8[1, Twofish_8x8[0, L[I]] xor B] xor A];
    DoXOR(@K, @Twofish_8x8[1], BoxKey[3].L shr 24);
    for I := 0 to 255 do
      L[I] := Twofish_8x8[0, K[I]];
    DoXOR(@L, @L, BoxKey[2].L shr 24);
    A := BoxKey[0].D;
    B := BoxKey[1].D;
    for I := 0 to 255 do
      Box[3, I] := Twofish_Data[3, Twofish_8x8[1, Twofish_8x8[1, L[I]] xor B] xor A];
  end;

begin
  SubKey := FAdditionalBuffer;
  Box    := @SubKey[40];
  SetupKey;
  if Size = 16 then
    SetupBox128
  else
  if Size = 24 then
    SetupBox192
  else
    SetupBox256;
end;

procedure TCipher_Twofish.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  S: PUInt32Array;
  Box: PTwofishBox;
  I, X, Y: UInt32;
  A, B, C, D: TLongRec;
begin
  Assert(Size = Context.BlockSize);

  S   := FAdditionalBuffer;
  A.L := PUInt32Array(Source)[0] xor S[0];
  B.L := PUInt32Array(Source)[1] xor S[1];
  C.L := PUInt32Array(Source)[2] xor S[2];
  D.L := PUInt32Array(Source)[3] xor S[3];

  Box := @S[40];
  S   := @S[8];
  for I := 0 to 7 do
  begin
    X := Box[0, A.A] xor Box[1, A.B] xor Box[2, A.C] xor Box[3, A.D];
    Y := Box[1, B.A] xor Box[2, B.B] xor Box[3, B.C] xor Box[0, B.D];
    D.L := D.L shl 1 or D.L shr 31;
    C.L := C.L xor (X + Y       + S[0]);
    D.L := D.L xor (X + Y shl 1 + S[1]);
    C.L := C.L shr 1 or C.L shl 31;

    X := Box[0, C.A] xor Box[1, C.B] xor Box[2, C.C] xor Box[3, C.D];
    Y := Box[1, D.A] xor Box[2, D.B] xor Box[3, D.C] xor Box[0, D.D];
    B.L := B.L shl 1 or B.L shr 31;
    A.L := A.L xor (X + Y       + S[2]);
    B.L := B.L xor (X + Y shl 1 + S[3]);
    A.L := A.L shr 1 or A.L shl 31;

    S := @S[4];
  end;
  S := FAdditionalBuffer;
  PUInt32Array(Dest)[0] := C.L xor S[4];
  PUInt32Array(Dest)[1] := D.L xor S[5];
  PUInt32Array(Dest)[2] := A.L xor S[6];
  PUInt32Array(Dest)[3] := B.L xor S[7];
end;

procedure TCipher_Twofish.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  S: PUInt32Array;
  Box: PTwofishBox;
  I, X, Y: UInt32;
  A, B, C, D: TLongRec;
begin
  Assert(Size = Context.BlockSize);

  S := FAdditionalBuffer;
  Box := @S[40];
  C.L := PUInt32Array(Source)[0] xor S[4];
  D.L := PUInt32Array(Source)[1] xor S[5];
  A.L := PUInt32Array(Source)[2] xor S[6];
  B.L := PUInt32Array(Source)[3] xor S[7];
  S := @S[36];
  for I := 0 to 7 do
  begin
    X := Box[0, C.A] xor Box[1, C.B] xor Box[2, C.C] xor Box[3, C.D];
    Y := Box[0, D.D] xor Box[1, D.A] xor Box[2, D.B] xor Box[3, D.C];
    A.L := A.L shl 1 or A.L shr 31;
    B.L := B.L xor (X + Y shl 1 + S[3]);
    A.L := A.L xor (X + Y       + S[2]);
    B.L := B.L shr 1 or B.L shl 31;

    X := Box[0, A.A] xor Box[1, A.B] xor Box[2, A.C] xor Box[3, A.D];
    Y := Box[0, B.D] xor Box[1, B.A] xor Box[2, B.B] xor Box[3, B.C];
    C.L := C.L shl 1 or C.L shr 31;
    D.L := D.L xor (X + Y shl 1 + S[1]);
    C.L := C.L xor (X + Y       + S[0]);
    D.L := D.L shr 1 or D.L shl 31;

    Dec(PUInt32(S), 4);
  end;
  S := FAdditionalBuffer;
  PUInt32Array(Dest)[0] := A.L xor S[0];
  PUInt32Array(Dest)[1] := B.L xor S[1];
  PUInt32Array(Dest)[2] := C.L xor S[2];
  PUInt32Array(Dest)[3] := D.L xor S[3];
end;

{ TCipher_IDEA }

class function TCipher_IDEA.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BufferSize                  := 8;
  Result.BlockSize                   := 8;
  Result.AdditionalBufferSize        := 208;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType := [ctSymmetric, ctBlock];
end;

procedure TCipher_IDEA.DoInit(const Key; Size: Integer);

  function IDEAInv(X: Word): Word;
  var
    A, B, C, D: Word;
  begin
    if X <= 1 then
    begin
      Result := X;
      Exit;
    end;
    A := 1;
    B := $10001 div X;
    C := $10001 mod X;
    while C <> 1 do
    begin
      D := X div C;
      X := X mod C;
      Inc(A, B * D);
      if X = 1 then
      begin
        Result := A;
        Exit;
      end;
      D := C div X;
      C := C mod X;
      Inc(B, A * D);
    end;
    Result := 1 - B;
  end;

var
  I: Integer;
  E: PWordArray;
  A, B, C: Word;
  K, D: PWordArray;
begin
  E := FAdditionalBuffer;
  Move(Key, E^, Size);
  for I := 0 to 7 do
    E[I] := Swap(E[I]);
  for I := 0 to 39 do
    E[I + 8] := E[I and not 7 + (I + 1) and 7] shl 9 or
                E[I and not 7 + (I + 2) and 7] shr 7;
  for I := 41 to 44 do
    E[I + 7] := E[I] shl 9 or E[I + 1] shr 7;
  K  := E;
  D  := @E[100];
  A  := IDEAInv(K[0]);
  B  := 0 - K[1];
  C  := 0 - K[2];
  D[3] := IDEAInv(K[3]);
  D[2] := C;
  D[1] := B;
  D[0] := A;
  Inc(PWord(K), 4);
  for I := 1 to 8 do
  begin
    Dec(PWord(D), 6);
    A    := K[0];
    D[5] := K[1];
    D[4] := A;
    A    := IDEAInv(K[2]);
    B    := 0 - K[3];
    C    := 0 - K[4];
    D[3] := IDEAInv(K[5]);
    D[2] := B;
    D[1] := C;
    D[0] := A;
    Inc(PWord(K), 6);
  end;
  A    := D[2];
  D[2] := D[1];
  D[1] := A;
end;

function IDEAMul(X, Y: UInt32): UInt32;
{$IF defined(X86ASM) or defined(X64ASM)}
asm
    {$IFDEF X64ASM}
       MOV    EAX,ECX
    {$ENDIF X64ASM}
       AND    EAX,0FFFFh
       JZ     @@1
       AND    EDX,0FFFFh
       JZ     @@1
       MUL    EDX
       MOV    EDX,EAX
       MOV    ECX,EAX
       SHR    EDX,16
       SUB    EAX,EDX
       SUB    CX,AX
       ADC    EAX,0
       RET
@@1:   LEA    EAX,[EAX + EDX - 1]
       NEG    EAX
end;
{$ELSE}
begin
  X := X and $FFFF;
  if X <> 0 then
  begin
    Y := Y and $FFFF;
    if Y <> 0 then
    begin
      X := X * Y;
      Result := X - (X shr 16);
      if Word(X) < Word(Result) then // carry flag check for "sub cx,ax"
        Inc(Result);
      Exit;
    end;
  end;
  Result := -(X + Y - 1);
end;
{$ENDIF}

procedure IDEACipher(Source, Dest: PUInt32Array; Key: PWordArray);
var
  I: UInt32;
  X, Y, A, B, C, D: UInt32;
begin
  I := SwapUInt32(Source[0]);
  A := I shr 16;
  B := I and $FFFF;
  I := SwapUInt32(Source[1]);
  C := I shr 16;
  D := I and $FFFF;
  for I := 0 to 7 do
  begin
    A := IDEAMul(A, Key[0]);
    Inc(B, Key[1]);
    Inc(C, Key[2]);
    D := IDEAMul(D, Key[3]);
    Y := C xor A;
    Y := IDEAMul(Y, Key[4]);
    X := B xor D + Y;
    X := IDEAMul(X, Key[5]);
    Inc(Y, X);
    A := A xor X;
    D := D xor Y;
    Y := B xor Y;
    B := C xor X;
    C := Y;
    Key := @Key[6];
  end;
  Dest[0] := SwapUInt32(IDEAMul(A, Key[0]) shl 16 or (C + Key[1]) and $FFFF);
  Dest[1] := SwapUInt32((B + Key[2]) shl 16 or IDEAMul(D, Key[3]) and $FFFF);
end;

procedure TCipher_IDEA.DoEncode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);

  IDEACipher(Source, Dest, FAdditionalBuffer);
end;

procedure TCipher_IDEA.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);

  IDEACipher(Source, Dest, @PUInt32Array(FAdditionalBuffer)[26]);
end;

{ TCipher_Cast256 }

class function TCipher_Cast256.Context: TCipherContext;
begin
  Result.KeySize                     := 32;
  Result.BlockSize                   := 16;
  Result.BufferSize                  := 16;
  Result.AdditionalBufferSize        := 384;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType := [ctSymmetric, ctBlock];
end;

procedure TCipher_Cast256.DoInit(const Key; Size: Integer);
var
  X: array[0..7] of UInt32;
  M, R, I, J, T: UInt32;
  K: PUInt32Array;
begin
  FillChar(X, SizeOf(X), 0);
  Move(Key, X, Size);
  SwapUInt32Buffer(X, X, 8);
  K := FAdditionalBuffer;
  M := $5A827999;
  R := 19;
  for I := 0 to 11 do
  begin
    for J := 0 to 1 do
    begin
      T := M + X[7];
      T := T shl R or T shr (32 - R);
      X[6] := X[6] xor (Cast256_Data[0, T shr 24] xor
                        Cast256_Data[1, T shr 16 and $FF] -
                        Cast256_Data[2, T shr  8 and $FF] +
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M xor X[6];
      T := T shl R or T shr (32 - R);
      X[5] := X[5] xor (Cast256_Data[0, T shr 24] -
                        Cast256_Data[1, T shr 16 and $FF] +
                        Cast256_Data[2, T shr  8 and $FF] xor
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M - X[5];
      T := T shl R or T shr (32 - R);
      X[4] := X[4] xor (Cast256_Data[0, T shr 24] +
                        Cast256_Data[1, T shr 16 and $FF] xor
                        Cast256_Data[2, T shr  8 and $FF] -
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M + X[4];
      T := T shl R or T shr (32 - R);
      X[3] := X[3] xor (Cast256_Data[0, T shr 24] xor
                        Cast256_Data[1, T shr 16 and $FF] -
                        Cast256_Data[2, T shr  8 and $FF] +
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M xor X[3];
      T := T shl R or T shr (32 - R);
      X[2] := X[2] xor (Cast256_Data[0, T shr 24] -
                        Cast256_Data[1, T shr 16 and $FF] +
                        Cast256_Data[2, T shr  8 and $FF] xor
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M - X[2];
      T := T shl R or T shr (32 - R);
      X[1] := X[1] xor (Cast256_Data[0, T shr 24] +
                        Cast256_Data[1, T shr 16 and $FF] xor
                        Cast256_Data[2, T shr  8 and $FF] -
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M + X[1];
      T := T shl R or T shr (32 - R);
      X[0] := X[0] xor (Cast256_Data[0, T shr 24] xor
                        Cast256_Data[1, T shr 16 and $FF] -
                        Cast256_Data[2, T shr  8 and $FF] +
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
      T := M xor X[0];
      T := T shl R or T shr (32 - R);
      X[7] := X[7] xor (Cast256_Data[0, T shr 24] -
                        Cast256_Data[1, T shr 16 and $FF] +
                        Cast256_Data[2, T shr  8 and $FF] xor
                        Cast256_Data[3, T and $FF]);
      Inc(M, $6ED9EBA1);
      Inc(R, 17);
    end;
    if I < 6 then
    begin
      K[48] := X[0] and $1F;
      K[49] := X[2] and $1F;
      K[50] := X[4] and $1F;
      K[51] := X[6] and $1F;
      K[0] := X[7];
      K[1] := X[5];
      K[2] := X[3];
      K[3] := X[1];
    end
    else
    begin
      K[48] := X[6] and $1F;
      K[49] := X[4] and $1F;
      K[50] := X[2] and $1F;
      K[51] := X[0] and $1F;
      K[0] := X[1];
      K[1] := X[3];
      K[2] := X[5];
      K[3] := X[7];
    end;
    K := @K[4];
  end;
  ProtectBuffer(X, SizeOf(X));
end;

procedure TCipher_Cast256.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I, T, A, B, C, D: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  SwapUInt32Buffer(Source^, Dest^, 4);
  A := PUInt32Array(Dest)[0];
  B := PUInt32Array(Dest)[1];
  C := PUInt32Array(Dest)[2];
  D := PUInt32Array(Dest)[3];
  for I := 0 to 5 do
  begin
    T := K[0] + D;
    T := T shl K[48] or T shr (32 - K[48]);
    C := C xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    T := K[1] xor C;
    T := T shl K[49] or T shr (32 - K[49]);
    B := B xor (Cast256_Data[0, T shr 24] -
                Cast256_Data[1, T shr 16 and $FF] +
                Cast256_Data[2, T shr  8 and $FF] xor
                Cast256_Data[3, T and $FF]);
    T := K[2] - B;
    T := T shl K[50] or T shr (32 - K[50]);
    A := A xor (Cast256_Data[0, T shr 24] +
                Cast256_Data[1, T shr 16 and $FF] xor
                Cast256_Data[2, T shr  8 and $FF] -
                Cast256_Data[3, T and $FF]);
    T := K[3] + A;
    T := T shl K[51] or T shr (32 - K[51]);
    D := D xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    K := @K[4];
  end;
  for I := 0 to 5 do
  begin
    T := K[0] + A;
    T := T shl K[48] or T shr (32 - K[48]);
    D := D xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    T := K[1] - B;
    T := T shl K[49] or T shr (32 - K[49]);
    A := A xor (Cast256_Data[0, T shr 24] +
                Cast256_Data[1, T shr 16 and $FF] xor
                Cast256_Data[2, T shr  8 and $FF] -
                Cast256_Data[3, T and $FF]);
    T := K[2] xor C;
    T := T shl K[50] or T shr (32 - K[50]);
    B := B xor (Cast256_Data[0, T shr 24] -
                Cast256_Data[1, T shr 16 and $FF] +
                Cast256_Data[2, T shr  8 and $FF] xor
                Cast256_Data[3, T and $FF]);
    T := K[3] + D;
    T := T shl K[51] or T shr (32 - K[51]);
    C := C xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    K := @K[4];
  end;
  PUInt32Array(Dest)[0] := A;
  PUInt32Array(Dest)[1] := B;
  PUInt32Array(Dest)[2] := C;
  PUInt32Array(Dest)[3] := D;
  SwapUInt32Buffer(Dest^, Dest^, 4);
end;

procedure TCipher_Cast256.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I, T, A, B, C, D: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := @PUInt32Array(FAdditionalBuffer)[44];
  SwapUInt32Buffer(Source^, Dest^, 4);
  A := PUInt32Array(Dest)[0];
  B := PUInt32Array(Dest)[1];
  C := PUInt32Array(Dest)[2];
  D := PUInt32Array(Dest)[3];
  for I := 0 to 5 do
  begin
    T := K[3] + D;
    T := T shl K[51] or T shr (32 - K[51]);
    C := C xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    T := K[2] xor C;
    T := T shl K[50] or T shr (32 - K[50]);
    B := B xor (Cast256_Data[0, T shr 24] -
                Cast256_Data[1, T shr 16 and $FF] +
                Cast256_Data[2, T shr  8 and $FF] xor
                Cast256_Data[3, T and $FF]);
    T := K[1] - B;
    T := T shl K[49] or T shr (32 - K[49]);
    A := A xor (Cast256_Data[0, T shr 24] +
                Cast256_Data[1, T shr 16 and $FF] xor
                Cast256_Data[2, T shr  8 and $FF] -
                Cast256_Data[3, T and $FF]);
    T := K[0] + A;
    T := T shl K[48] or T shr (32 - K[48]);
    D := D xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    Dec(PUInt32(K), 4);
  end;
  for I := 0 to 5 do
  begin
    T := K[3] + A;
    T := T shl K[51] or T shr (32 - K[51]);
    D := D xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    T := K[2] - B;
    T := T shl K[50] or T shr (32 - K[50]);
    A := A xor (Cast256_Data[0, T shr 24] +
                Cast256_Data[1, T shr 16 and $FF] xor
                Cast256_Data[2, T shr  8 and $FF] -
                Cast256_Data[3, T and $FF]);
    T := K[1] xor C;
    T := T shl K[49] or T shr (32 - K[49]);
    B := B xor (Cast256_Data[0, T shr 24] -
                Cast256_Data[1, T shr 16 and $FF] +
                Cast256_Data[2, T shr  8 and $FF] xor
                Cast256_Data[3, T and $FF]);
    T := K[0] + D;
    T := T shl K[48] or T shr (32 - K[48]);
    C := C xor (Cast256_Data[0, T shr 24] xor
                Cast256_Data[1, T shr 16 and $FF] -
                Cast256_Data[2, T shr  8 and $FF] +
                Cast256_Data[3, T and $FF]);
    Dec(PUInt32(K), 4);
  end;
  PUInt32Array(Dest)[0] := A;
  PUInt32Array(Dest)[1] := B;
  PUInt32Array(Dest)[2] := C;
  PUInt32Array(Dest)[3] := D;
  SwapUInt32Buffer(Dest^, Dest^, 4);
end;

{ TCipher_Mars }

class function TCipher_Mars.Context: TCipherContext;
begin
  Result.KeySize                     := 56;
  Result.BlockSize                   := 16;
  Result.BufferSize                  := 16;
  Result.AdditionalBufferSize        := 160;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Mars.DoInit(const Key; Size: Integer);
var
  B: PUInt32Array;

  function FixKey(K, R: UInt32): UInt32;
  var
    M1, M2: UInt32;
    I: UInt32;
  begin
    I := K and 3;
    K := K or 3;
    M1 := not K xor (K shl 1);
    M2 := M1 and (M1 shl 1);
    M2 := M2 and (M2 shl 2);
    M2 := M2 and (M2 shl 4);
    M2 := M2 and (M1 shl 8);
    M2 := M2 and $FFFFFE00;
    if M2 = 0 then
    begin
      Result := K;
      Exit;
    end;
    M1 := M2 or (M2 shr 1);
    M1 := M1 or (M1 shr 2);
    M1 := M1 or (M2 shr 4);
    M1 := M1 or (M1 shr 5);
    M1 := M1 and ((not K xor (K shl 1)) and (not K xor (K shr 1)) and $7FFFFFFC);
    Result := K xor ((B[265 + I] shl R or B[265 + I] shr (32 - R)) and M1);
  end;

var
  T: array[0..14] of UInt32;
  I, J, L: UInt32;
  U: UInt32;
  K: PUInt32Array;
begin
  K := FAdditionalBuffer;
  B := @Mars_Data;
  FillChar(T, SizeOf(T), 0);
  Move(Key, T, Size);
  Size := Size div 4;
  T[Size] := Size;
  for J := 0 to 3 do
  begin
    for I := 0 to 14 do
    begin
      U := T[(I + 8) mod 15] xor T[(I + 13) mod 15];
      T[I] := T[I] xor (U shl 3 or U shr 29) xor (I * 4 + J);
    end;
    for L := 0 to 3 do
    begin
      for I := 0 to 14 do
      begin
        Inc(T[I], B[T[(I + 14) mod 15] and $1FF]);
        T[I] := T[I] shl 9 or T[I] shr 23;
      end;
    end;
    for I := 0 to 9 do
      K[(J * 10) + I] := T[(I * 4) mod 15];
  end;
  I := 5;
  repeat
    K[I] := FixKey(K[I], K[I - 1]);
    Inc(I, 2);
  until I >= 37;
end;

procedure TCipher_Mars.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  K: PUInt32Array;
  I, L, R, A, B, C, D: UInt32;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  A := PUInt32Array(Source)[0] + K[0];
  B := PUInt32Array(Source)[1] + K[1];
  C := PUInt32Array(Source)[2] + K[2];
  D := PUInt32Array(Source)[3] + K[3];
  K := @K[4];
  for I := 0 to 1 do
  begin
    B := B xor Mars_Data[A and $FF] + Mars_Data[A shr 8 and $FF + 256];
    Inc(C, Mars_Data[A shr 16 and $FF]);
    D := D xor Mars_Data[A shr 24 + 256];
    A := (A shr 24 or A shl 8) + D;

    C := C xor Mars_Data[B and $FF] + Mars_Data[B shr 8 and $FF + 256];
    Inc(D, Mars_Data[B shr 16 and $FF]);
    A := A xor Mars_Data[B shr 24 + 256];
    B := (B shr 24 or B shl 8) + C;

    D := D xor Mars_Data[C and $FF] + Mars_Data[C shr 8 and $FF + 256];
    Inc(A, Mars_Data[C shr 16 and $FF]);
    B := B xor Mars_Data[C shr 24 + 256];
    C := C shr 24 or C shl 8;

    A := A xor Mars_Data[D and $FF] + Mars_Data[D shr 8 and $FF + 256];
    Inc(B, Mars_Data[D shr 16 and $FF]);
    C := C xor Mars_Data[D shr 24 + 256];
    D := D shr 24 or D shl 8;
  end;

  for I := 0 to 3 do
  begin
    L := A + K[0];
    A := A shl 13 or A shr 19;
    R := A * K[1];
    R := R shl 5 or R shr 27;
    Inc(C, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);

    if I <= 1 then
    begin
      Inc(B, L);
      D := D xor R;
    end
    else
    begin
      Inc(D, L);
      B := B xor R;
    end;
    L := B + K[2];
    B := B shl 13 or B shr 19;
    R := B * K[3];
    R := R shl 5 or R shr 27;
    Inc(D, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Inc(C, L);
      A := A xor R;
    end
    else
    begin
      Inc(A, L);
      C := C xor R;
    end;
    L := C + K[4];
    C := C shl 13 or C shr 19;
    R := C * K[5];
    R := R shl 5 or R shr 27;
    Inc(A, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Inc(D, L);
      B := B xor R;
    end
    else
    begin
      Inc(B, L);
      D := D xor R;
    end;
    L := D + K[6];
    D := D shl 13 or D shr 19;
    R := D * K[7];
    R := R shl 5 or R shr 27;
    Inc(B, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Inc(A, L);
      C := C xor R;
    end
    else
    begin
      Inc(C, L);
      A := A xor R;
    end;
    K := @K[8];
  end;
  for I := 0 to 1 do
  begin
    B := B xor Mars_Data[A and $FF + 256];
    Dec(C, Mars_Data[A shr 24]);
    D := D - Mars_Data[A shr 16 and $FF + 256] xor Mars_Data[A shr 8 and $FF];
    A := A shl 24 or A shr 8;
    C := C xor Mars_Data[B and $FF + 256];
    Dec(D, Mars_Data[B shr 24]);
    A := A - Mars_Data[B shr 16 and $FF + 256] xor Mars_Data[B shr 8 and $FF];
    B := B shl 24 or B shr 8;
    Dec(C, B);
    D := D xor Mars_Data[C and $FF + 256];
    Dec(A, Mars_Data[C shr 24]);
    B := B - Mars_Data[C shr 16 and $FF + 256] xor Mars_Data[C shr 8 and $FF];
    C := C shl 24 or C shr 8;
    Dec(D, A);
    A := A xor Mars_Data[D and $FF + 256];
    Dec(B, Mars_Data[D shr 24]);
    C := C - Mars_Data[D shr 16 and $FF + 256] xor Mars_Data[D shr 8 and $FF];
    D := D shl 24 or D shr 8;
  end;
  PUInt32Array(Dest)[0] := A - K[0];
  PUInt32Array(Dest)[1] := B - K[1];
  PUInt32Array(Dest)[2] := C - K[2];
  PUInt32Array(Dest)[3] := D - K[3];
end;

procedure TCipher_Mars.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  K: PUInt32Array;
  I, L, R, A, B, C, D: UInt32;
begin
  Assert(Size = Context.BlockSize);

  K := @PUInt32Array(FAdditionalBuffer)[28];
  A := PUInt32Array(Source)[0] + K[8];
  B := PUInt32Array(Source)[1] + K[9];
  C := PUInt32Array(Source)[2] + K[10];
  D := PUInt32Array(Source)[3] + K[11];
  for I := 0 to 1 do
  begin
    D := D shr 24 or D shl 8;
    C := C xor Mars_Data[D shr 8 and $FF] + Mars_Data[D shr 16 and $FF + 256];
    Inc(B, Mars_Data[D shr 24]);
    A := A xor Mars_Data[D and $FF + 256];
    Inc(D, A);
    C := C shr 24 or C shl 8;
    B := B xor Mars_Data[C shr 8 and $FF] + Mars_Data[C shr 16 and $FF + 256];
    Inc(A, Mars_Data[C shr 24]);
    D := D xor Mars_Data[C and $FF + 256];
    Inc(C, B);
    B := B shr 24 or B shl 8;
    A := A xor Mars_Data[B shr 8 and $FF] + Mars_Data[B shr 16 and $FF + 256];
    Inc(D, Mars_Data[B shr 24]);
    C := C xor Mars_Data[B and $FF + 256];
    A := A shr 24 or A shl 8;
    D := D xor Mars_Data[A shr 8 and $FF] + Mars_Data[A shr 16 and $FF + 256];
    Inc(C, Mars_Data[A shr 24]);
    B := B xor Mars_Data[A and $FF + 256];
  end;
  for I := 0 to 3 do
  begin
    R := D * K[7];
    R := R shl 5 or R shr 27;
    D := D shr 13 or D shl 19;
    L := D + K[6];
    Dec(B, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Dec(C, L);
      A := A xor R;
    end
    else
    begin
      Dec(A, L);
      C := C xor R;
    end;
    R := C * K[5];
    R := R shl 5 or R shr 27;
    C := C shr 13 or C shl 19;
    L := C + K[4];
    Dec(A, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Dec(B, L);
      D := D xor R;
    end
    else
    begin
      Dec(D, L);
      B := B xor R;
    end;
    R := B * K[3];
    R := R shl 5 or R shr 27;
    B := B shr 13 or B shl 19;
    L := B + K[2];
    Dec(D, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Dec(A, L);
      C := C xor R;
    end
    else
    begin
      Dec(C, L);
      A := A xor R;
    end;
    R := A * K[1];
    R := R shl 5 or R shr 27;
    A := A shr 13 or A shl 19;
    L := A + K[0];
    Dec(C, L shl R or L shr (32 - R));
    L := Mars_Data[L and $1FF] xor R;
    R := R shl 5 or R shr 27;
    L := L xor R;
    L := L shl R or L shr (32 - R);
    if I <= 1 then
    begin
      Dec(D, L);
      B := B xor R;
    end
    else
    begin
      Dec(B, L);
      D := D xor R;
    end;
    Dec(PUInt32(K), 8);
  end;
  for I := 0 to 1 do
  begin
    D := D shl 24 or D shr 8;
    C := C xor Mars_Data[D shr 24 + 256];
    Dec(B, Mars_Data[D shr 16 and $FF]);
    A := A - Mars_Data[D shr 8 and $FF + 256] xor Mars_Data[D and $FF];
    C := C shl 24 or C shr 8;
    B := B xor Mars_Data[C shr 24 + 256];
    Dec(A, Mars_Data[C shr 16 and $FF]);
    D := D - Mars_Data[C shr 8 and $FF + 256] xor Mars_Data[C and $FF];
    Dec(B, C);
    B := B shl 24 or B shr 8;
    A := A xor Mars_Data[B shr 24 + 256];
    Dec(D, Mars_Data[B shr 16 and $FF]);
    C := C - Mars_Data[B shr 8 and $FF + 256] xor Mars_Data[B and $FF];
    Dec(A, D);
    A := A shl 24 or A shr 8;
    D := D xor Mars_Data[A shr 24 + 256];
    Dec(C, Mars_Data[A shr 16 and $FF]);
    B := B - Mars_Data[A shr 8 and $FF + 256] xor Mars_Data[A and $FF];
  end;
  PUInt32Array(Dest)[0] := A - K[4];
  PUInt32Array(Dest)[1] := B - K[5];
  PUInt32Array(Dest)[2] := C - K[6];
  PUInt32Array(Dest)[3] := D - K[7];
end;

{ TCipher_RC4 }

class function TCipher_RC4.Context: TCipherContext;
begin
  Result.KeySize                     := 256;
  Result.BlockSize                   := 1;
  Result.BufferSize                  := 16;
  Result.AdditionalBufferSize        := 256 + 2;
  Result.NeedsAdditionalBufferBackup := true;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctStream];
end;

procedure TCipher_RC4.DoInit(const Key; Size: Integer);
var
  K: array[0..255] of Byte;
  D: PByteArray;
  I, J, T: Byte;
begin
  D := FAdditionalBuffer;
  for I := 0 to 255 do
  begin
    D[I] := I;
    if Size > 0 then
      K[I] := TByteArray(Key)[I mod Size];
  end;
  J := 0;
  for I := 0 to 255 do
  begin
    J := J + D[I] + K[I];
    T := D[I];
    D[I] := D[J];
    D[J] := T;
  end;
  D[256] := 0;
  D[257] := 0;
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_RC4.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  D: PByteArray;
  S: Integer;
  T, I, J: Byte;
begin
  D := FAdditionalBuffer;
  I := D[256];
  J := D[257];
  for S := 0 to Size - 1 do
  begin
    Inc(I);
    T := D[I];
    Inc(J, T);
    D[I] := D[J];
    D[J] := T;
    PByteArray(Dest)[S] := PByteArray(Source)[S] xor D[Byte(D[I] + T)];
  end;
  D[256] := I;
  D[257] := J;
end;

procedure TCipher_RC4.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  DoEncode(Source, Dest, Size);
end;

{ TCipher_RC6 }

class function TCipher_RC6.Context: TCipherContext;
begin
  Result.KeySize                     := 256;
  Result.BlockSize                   := 16;
  Result.BufferSize                  := 16;
  Result.AdditionalBufferSize        := 272;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 16;
  Result.MaxRounds                   := 24;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_RC6.SetRounds(Value: Integer);
begin
  if Value < Context.MinRounds then
    Value := Context.MinRounds
  else
  if Value > Context.MaxRounds then
    Value := Context.MaxRounds;
  if Value <> FRounds then
  begin
    if not (FState in [csNew, csInitialized, csDone]) then
      Done;
    FRounds := Value;
  end;
end;

procedure TCipher_RC6.DoInit(const Key; Size: Integer);
var
  K: array[0..63] of UInt32;
  D: PUInt32Array;
  I, J, L, A, B, Z, T: UInt32;
begin
  LimitRounds;

  D := FAdditionalBuffer;
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  L := Size shr 2;
  if Size and 3 <> 0 then
    Inc(L);
  if L <= 0 then
    L := 1;
  J := $B7E15163;
  for I := 0 to (FRounds + 2) * 2 do
  begin
    D[I] := J;
    Inc(J, $9E3779B9);
  end;
  if L > UInt32(FRounds + 2) * 2 then
    Z := L * 3
  else
    Z := (FRounds + 2) * 6;
  I := 0;
  J := 0;
  A := 0;
  B := 0;
  for Z := Z downto 1 do
  begin
    A := A + B + D[I];
    A := A shl 3 or A shr 29;
    D[I] := A;
    T := A + B;
    B := T + K[J];
    B := B shl T or B shr (32 - T);
    K[J] := B;
    I := (I + 1) mod (UInt32(FRounds + 2) * 2);
    J := (J + 1) mod L;
  end;
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_RC6.LimitRounds;
begin
  if FRounds = 0 then
    FRounds := 20
  else
  if FRounds < 16 then
    FRounds := 16
  else
  if FRounds > 24 then
    FRounds := 24;
end;

procedure TCipher_RC6.DoEncode(Source, Dest: Pointer; Size: Integer);
{$IFDEF X86ASM}
asm
      PUSH  EBX
      PUSH  ESI
      PUSH  EDI
      PUSH  EBP
      PUSH  ECX
      MOV   EBP,[EAX].TCipher_RC6.FRounds           // Rounds
      MOV   ESI,[EAX].TCipher_RC6.FAdditionalBuffer // Key
      MOV   EAX,[EDX +  0]    // A
      MOV   EBX,[EDX +  4]    // B
      MOV   EDI,[EDX +  8]    // C
      MOV   EDX,[EDX + 12]    // D
      ADD   EBX,[ESI + 0]     // Inc(B, K[0])
      ADD   EDX,[ESI + 4]     // Inc(D, K[1])
      ADD   ESI,8             // Inc(PInteger(K), 2)
@@1:  LEA   ECX,[EBX * 2 + 1] // ECX := B * 2 + 1
      IMUL  ECX,EBX           // ECX := ECX * B
      ROL   ECX,5             // T := ROL(B * (B * 2 + 1), 5)
      PUSH  ECX               // save T
      XOR   EAX,ECX           // A := A xor T
      LEA   ECX,[EDX * 2 + 1] // ECX := D * 2 + 1
      IMUL  ECX,EDX           // ECX := ECX * D
      ROL   ECX,5             // U := ROL(D * (D * 2 + 1), 5)
      XOR   EDI,ECX           // C := C xor U
      ROL   EAX,CL            // A := ROL(A xor T, U)
      POP   ECX               // restore T
      ADD   EAX,[ESI + 0]     // Inc(A, K[0])
      ROL   EDI,CL            // C := ROL(C xor U, T)
      MOV   ECX,EAX           // T := A
      ADD   EDI,[ESI + 4]     // Inc(C, K[1])
      MOV   EAX,EBX           // A := B
      MOV   EBX,EDI           // B := C
      MOV   EDI,EDX           // C := D
      DEC   EBP
      MOV   EDX,ECX           // D := T;
      LEA   ESI,[ESI + 8]     // Inc(PInteger(K), 2)
      JNZ   @@1
      ADD   EAX,[ESI + 0]     // Inc(A, K[0])
      ADD   EDI,[ESI + 4]     // Inc(C, K[1])
      POP   ECX
      MOV   [ECX +  0],EAX    // A
      MOV   [ECX +  4],EBX    // B
      MOV   [ECX +  8],EDI    // C
      MOV   [ECX + 12],EDX    // D
      POP   EBP
      POP   EDI
      POP   ESI
      POP   EBX
end;
{$ELSE !X86ASM}
var
  K: PUInt32Array;
  I, T, U, A, B, C, D: UInt32;
begin
  Assert(Size = Context.BlockSize);

  K := Pointer(FBuffer);
  A := PUInt32Array(Source)[0];
  B := PUInt32Array(Source)[1] + K[0];
  C := PUInt32Array(Source)[2];
  D := PUInt32Array(Source)[3] + K[1];
  for I := 1 to FRounds do
  begin
    K := @K[2];
    T := B * (B + B + 1);
    T := T shl 5 or T shr 27;
    U := D * (D + D + 1);
    U := U shl 5 or U shr 27;
    A := A xor T;
    A := A shl U or A shr (32 - U) + K[0];
    C := C xor U;
    C := C shl T or C shr (32 - T) + K[1];
    T := A; A := B; B := C; C := D; D := T;
  end;
  PUInt32Array(Dest)[0] := A + K[2];
  PUInt32Array(Dest)[1] := B;
  PUInt32Array(Dest)[2] := C + K[3];
  PUInt32Array(Dest)[3] := D;
end;
{$ENDIF !X86ASM}

procedure TCipher_RC6.DoDecode(Source, Dest: Pointer; Size: Integer);
{$IFDEF X86ASM}
asm
      PUSH  EBX
      PUSH  ESI
      PUSH  EDI
      PUSH  EBP
      PUSH  ECX
      MOV   EBP,[EAX].TCipher_RC6.FRounds           // Rounds
      MOV   ESI,[EAX].TCipher_RC6.FAdditionalBuffer // Key
      LEA   ESI,[ESI + EBP * 8]                     // Key[FRounds * 2]
      MOV   EAX,[EDX +  0]    // A
      MOV   EBX,[EDX +  4]    // B
      MOV   EDI,[EDX +  8]    // C
      MOV   EDX,[EDX + 12]    // D
      SUB   EDI,[ESI + 12]    // Dec(C, K[3])
      SUB   EAX,[ESI +  8]    // Dec(A, K[2])
@@1:  MOV   ECX,EAX           // T := A
      SUB   EDX,[ESI + 0]     // Dec(A, K[0])
      MOV   EAX,EDX           // A := D
      MOV   EDX,EDI           // D := C
      SUB   EBX,[ESI + 4]     // Dec(C, K[1])
      MOV   EDI,EBX           // C := B
      MOV   EBX,ECX           // B := T;
      LEA   ECX,[EDX * 2 + 1] // ECX := D * 2 + 1
      IMUL  ECX,EDX           // ECX := ECX * D
      ROL   ECX,5             // U := ROL(D * (D * 2 + 1), 5)
      PUSH  ECX               // save U
      ROR   EAX,CL            // A := ROR(A - K[0], U)
      LEA   ECX,[EBX * 2 + 1] // ECX := B * 2 + 1
      IMUL  ECX,EBX           // ECX := ECX * B
      ROL   ECX,5             // T := ROL(B * (B * 2 + 1), 5)
      XOR   EAX,ECX           // A := A xor T
      ROR   EDI,CL            // C := ROR(C - K[1], T)
      POP   ECX               // restore U
      XOR   EDI,ECX           // C := C xor U
      DEC   EBP
      LEA   ESI,[ESI - 8]     // Dec(PInteger(K), 2)
      JNZ   @@1
      SUB   EBX,[ESI + 0]     // Dec(B, K[0])
      SUB   EDX,[ESI + 4]     // Inc(D, K[1])
      POP   ECX
      MOV   [ECX +  0],EAX    // A
      MOV   [ECX +  4],EBX    // B
      MOV   [ECX +  8],EDI    // C
      MOV   [ECX + 12],EDX    // D
      POP   EBP
      POP   EDI
      POP   ESI
      POP   EBX
end;
{$ELSE !X86ASM}
var
  I, U, T, A, B, C, D: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := @PUInt32Array(FBuffer)[FRounds * 2];
  A := PUInt32Array(Source)[0] - K[2];
  B := PUInt32Array(Source)[1];
  C := PUInt32Array(Source)[2] - K[3];
  D := PUInt32Array(Source)[3];

  for I := 1 to FRounds do
  begin
    T := A; A := D; D := C; C := B; B := T;
    U := D * (D + D + 1);
    U := U shl 5 or U shr 27;
    T := B * (B + B + 1);
    T := T shl 5 or T shr 27;
    C := C - K[1];
    C := C shr T or C shl (32 - T) xor U;
    A := A - K[0];
    A := A shr U or A shl (32 - U) xor T;
    Dec(PUInt32(K), 2);
  end;

  PUInt32Array(Dest)[0] := A;
  PUInt32Array(Dest)[1] := B - K[0];
  PUInt32Array(Dest)[2] := C;
  PUInt32Array(Dest)[3] := D - K[1];
end;
{$ENDIF !X86ASM}

{ TCipher_Rijndael }

class function TCipher_Rijndael.Context: TCipherContext;
const
  // don't change this!
  Rijndael_Blocks =  4;
  Rijndael_Rounds = 14;
begin
  Result.KeySize                     := 32;
  Result.BlockSize                   := Rijndael_Blocks * 4;
  Result.BufferSize                  := Rijndael_Blocks * 4;
  Result.AdditionalBufferSize        := (Rijndael_Rounds + 1) * Rijndael_Blocks * SizeOf(UInt32) * 2;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Rijndael.DoInit(const Key; Size: Integer);
{
  // Old Rijndael Key Scheduling:

  procedure BuildEncodeKey;
  const
    RND_Data: array[0..29] of Byte = (
      $01, $02, $04, $08, $10, $20, $40, $80, $1B, $36, $6C, $D8, $AB, $4D, $9A,
      $2F, $5E, $BC, $63, $C6, $97, $35, $6A, $D4, $B3, $7D, $FA, $EF, $C5, $91
    );
  var
    T, R: Integer;

    procedure NextRounds;
    var
      J: Integer;
    begin
      J := 0;
      while (J < FRounds - 6) and (R <= FRounds) do
      begin
        while (J < FRounds - 6) and (T < Rijndael_Blocks) do
        begin
          PUInt32Array(FBuffer)[R * Rijndael_Blocks + T] := K[J];
          Inc(J);
          Inc(T);
        end;
        if T = Rijndael_Blocks then
        begin
          T := 0;
          Inc(R);
        end;
      end;
    end;

  var
    RND: PByte;
    B: PByte;
    I: Integer;
  begin
    R := 0;
    T := 0;
    RND := @RND_Data;
    NextRounds;
    while R <= FRounds do
    begin
      B  := @K;
      B^ := B^ xor Rijndael_S[0, K[FRounds - 7] shr  8 and $FF] xor RND^; Inc(B);
      B^ := B^ xor Rijndael_S[0, K[FRounds - 7] shr 16 and $FF];          Inc(B);
      B^ := B^ xor Rijndael_S[0, K[FRounds - 7] shr 24];                  Inc(B);
      B^ := B^ xor Rijndael_S[0, K[FRounds - 7] and $FF];
      Inc(RND);
      if FRounds = 14 then
      begin
        for I := 1 to 7 do
          K[I] := K[I] xor K[I - 1];
        B  := @K[4];
        B^ := B^ xor Rijndael_S[0, K[3] and $FF];         Inc(B);
        B^ := B^ xor Rijndael_S[0, K[3] shr  8 and $FF];  Inc(B);
        B^ := B^ xor Rijndael_S[0, K[3] shr 16 and $FF];  Inc(B);
        B^ := B^ xor Rijndael_S[0, K[3] shr 24];
        for I := 5 to 7 do
          K[I] := K[I] xor K[I - 1];
      end
      else
        for I := 1 to FRounds - 7 do
          K[I] := K[I] xor K[I - 1];
      NextRounds;
    end;
  end;

  procedure BuildDecodeKey;
  var
    I: Integer;
    D: PUInt32;
  begin
    D := Pointer(PAnsiChar(FBuffer) + FBufferSize shr 1); // for Pointer Math
    Move(FBuffer^, D^, FBufferSize shr 1);
    Inc(D, 4);
    for I := 0 to FRounds * 4 - 5 do
    begin
      D^ :=  Rijndael_Key[D^ and $FF] xor
            (Rijndael_Key[D^ shr  8 and $FF] shl  8 or Rijndael_Key[D^ shr  8 and $FF] shr 24) xor
            (Rijndael_Key[D^ shr 16 and $FF] shl 16 or Rijndael_Key[D^ shr 16 and $FF] shr 16) xor
            (Rijndael_Key[D^ shr 24]         shl 24 or Rijndael_Key[D^ shr 24]          shr 8);
      Inc(D);
    end;
  end; }

  // New AES conform Key Scheduling

  procedure BuildEncodeKey;
  const
    RCon: array[0..9] of UInt32 = ($01, $02, $04, $08, $10, $20, $40, $80, $1b, $36);
  var
    I: Integer;
    T: UInt32;
    P: PUInt32Array;
  begin
    P := FAdditionalBuffer;
    if Size <= 16 then
    begin
      for I := 0 to 9 do
      begin
        T := P[3];
        P[4] := Rijndael_S[0, T shr  8 and $FF]        xor
                Rijndael_S[0, T shr 16 and $FF] shl  8 xor
                Rijndael_S[0, T shr 24        ] shl 16 xor
                Rijndael_S[0, T        and $FF] shl 24 xor P[0] xor RCon[I];
        P[5] := P[1] xor P[4];
        P[6] := P[2] xor P[5];
        P[7] := P[3] xor P[6];
        P    := @P[4];
      end;
    end
    else
      if Size <= 24 then
      begin
        for I := 0 to 7 do
        begin
          T := P[5];
          P[6] := Rijndael_S[0, T shr  8 and $FF]        xor
                  Rijndael_S[0, T shr 16 and $FF] shl  8 xor
                  Rijndael_S[0, T shr 24        ] shl 16 xor
                  Rijndael_S[0, T        and $FF] shl 24 xor P[0] xor RCon[I];
          P[7] := P[1] xor P[6];
          P[8] := P[2] xor P[7];
          P[9] := P[3] xor P[8];
          if I = 7 then
            Break;
          P[10] := P[4] xor P[9];
          P[11] := P[5] xor P[10];
          P     := @P[6];
        end;
      end
      else
      begin
        for I :=0 to 6 do
        begin
          T := P[7];
          P[8] := Rijndael_S[0, T shr  8 and $FF]        xor
                  Rijndael_S[0, T shr 16 and $FF] shl  8 xor
                  Rijndael_S[0, T shr 24        ] shl 16 xor
                  Rijndael_S[0, T        and $FF] shl 24 xor P[0] xor RCon[I];
          P[9] := P[1] xor P[8];
          P[10] := P[2] xor P[9];
          P[11] := P[3] xor P[10];
          if I = 6 then
            Break;
          T := P[11];
          P[12] := Rijndael_S[0, T        and $FF]        xor
                   Rijndael_S[0, T shr  8 and $FF] shl  8 xor
                   Rijndael_S[0, T shr 16 and $FF] shl 16 xor
                   Rijndael_S[0, T shr 24        ] shl 24 xor P[4];
          P[13] := P[5] xor P[12];
          P[14] := P[6] xor P[13];
          P[15] := P[7] xor P[14];
          P     := @P[8];
        end;
      end;
  end;

  procedure BuildDecodeKey;
  var
    P: PUInt32;
    I: Integer;
  begin
    P := Pointer(PByte(FAdditionalBuffer) + FAdditionalBufferSize shr 1); // for Pointer Math
    Move(FAdditionalBuffer^, P^, FAdditionalBufferSize shr 1);
    Inc(P, 4);
    for I := 0 to FRounds * 4 - 5 do
    begin
      P^ := Rijndael_T[4, Rijndael_S[0, P^        and $FF]] xor
            Rijndael_T[5, Rijndael_S[0, P^ shr  8 and $FF]] xor
            Rijndael_T[6, Rijndael_S[0, P^ shr 16 and $FF]] xor
            Rijndael_T[7, Rijndael_S[0, P^ shr 24        ]];
      Inc(P);
    end;
  end;

begin
  if Size <= 16 then
    FRounds := 10
  else
  if Size <= 24 then
    FRounds := 12
  else
    FRounds := 14;
  FillChar(FAdditionalBuffer^, 32, 0);
  Move(Key, FAdditionalBuffer^, Size);
  BuildEncodeKey;
  BuildDecodeKey;
end;

procedure TCipher_Rijndael.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  P: PUInt32Array;
  I: Integer;
  A2, B2, C2, D2: UInt32;
  A1, B1, C1, D1: UInt32;
begin
  Assert(Size = Context.BlockSize);

  P  := FAdditionalBuffer;
  A1 := PUInt32Array(Source)[0];
  B1 := PUInt32Array(Source)[1];
  C1 := PUInt32Array(Source)[2];
  D1 := PUInt32Array(Source)[3];

  for I := 2 to FRounds do
  begin
    A2 := A1 xor P[0];
    B2 := B1 xor P[1];
    C2 := C1 xor P[2];
    D2 := D1 xor P[3];

    A1 := Rijndael_T[0, A2        and $FF] xor
          Rijndael_T[1, B2 shr  8 and $FF] xor
          Rijndael_T[2, C2 shr 16 and $FF] xor
          Rijndael_T[3, D2 shr 24        ];
    B1 := Rijndael_T[0, B2        and $FF] xor
          Rijndael_T[1, C2 shr  8 and $FF] xor
          Rijndael_T[2, D2 shr 16 and $FF] xor
          Rijndael_T[3, A2 shr 24        ];
    C1 := Rijndael_T[0, C2        and $FF] xor
          Rijndael_T[1, D2 shr  8 and $FF] xor
          Rijndael_T[2, A2 shr 16 and $FF] xor
          Rijndael_T[3, B2 shr 24        ];
    D1 := Rijndael_T[0, D2        and $FF] xor
          Rijndael_T[1, A2 shr  8 and $FF] xor
          Rijndael_T[2, B2 shr 16 and $FF] xor
          Rijndael_T[3, C2 shr 24        ];

    P := @P[4];
  end;

  A2 := A1 xor P[0];
  B2 := B1 xor P[1];
  C2 := C1 xor P[2];
  D2 := D1 xor P[3];

  PUInt32Array(Dest)[0] := (Rijndael_S[0, A2        and $FF]        or
                          Rijndael_S[0, B2 shr  8 and $FF] shl  8 or
                          Rijndael_S[0, C2 shr 16 and $FF] shl 16 or
                          Rijndael_S[0, D2 shr 24        ] shl 24)     xor P[4];
  PUInt32Array(Dest)[1] := (Rijndael_S[0, B2        and $FF]        or
                          Rijndael_S[0, C2 shr  8 and $FF] shl  8 or
                          Rijndael_S[0, D2 shr 16 and $FF] shl 16 or
                          Rijndael_S[0, A2 shr 24        ] shl 24)     xor P[5];
  PUInt32Array(Dest)[2] := (Rijndael_S[0, C2        and $FF]        or
                          Rijndael_S[0, D2 shr  8 and $FF] shl  8 or
                          Rijndael_S[0, A2 shr 16 and $FF] shl 16 or
                          Rijndael_S[0, B2 shr 24        ] shl 24)     xor P[6];
  PUInt32Array(Dest)[3] := (Rijndael_S[0, D2        and $FF]        or
                          Rijndael_S[0, A2 shr  8 and $FF] shl  8 or
                          Rijndael_S[0, B2 shr 16 and $FF] shl 16 or
                          Rijndael_S[0, C2 shr 24        ] shl 24)     xor P[7];
end;

procedure TCipher_Rijndael.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  P: PUInt32Array;
  I: Integer;
  A2, B2, C2, D2: UInt32;
  A1, B1, C1, D1: UInt32;
begin
  Assert(Size = Context.BlockSize);

  P  := Pointer(PByte(FAdditionalBuffer) + FAdditionalBufferSize shr 1 + FRounds * 16); // for Pointer Math
  A1 := PUInt32Array(Source)[0];
  B1 := PUInt32Array(Source)[1];
  C1 := PUInt32Array(Source)[2];
  D1 := PUInt32Array(Source)[3];

  for I := 2 to FRounds do
  begin
    A2 := A1 xor P[0];
    B2 := B1 xor P[1];
    C2 := C1 xor P[2];
    D2 := D1 xor P[3];

    A1 := Rijndael_T[4, A2        and $FF] xor
          Rijndael_T[5, D2 shr  8 and $FF] xor
          Rijndael_T[6, C2 shr 16 and $FF] xor
          Rijndael_T[7, B2 shr 24        ];
    B1 := Rijndael_T[4, B2        and $FF] xor
          Rijndael_T[5, A2 shr  8 and $FF] xor
          Rijndael_T[6, D2 shr 16 and $FF] xor
          Rijndael_T[7, C2 shr 24        ];
    C1 := Rijndael_T[4, C2        and $FF] xor
          Rijndael_T[5, B2 shr  8 and $FF] xor
          Rijndael_T[6, A2 shr 16 and $FF] xor
          Rijndael_T[7, D2 shr 24        ];
    D1 := Rijndael_T[4, D2        and $FF] xor
          Rijndael_T[5, C2 shr  8 and $FF] xor
          Rijndael_T[6, B2 shr 16 and $FF] xor
          Rijndael_T[7, A2 shr 24        ];

    Dec(PUInt32(P), 4);
  end;

  A2 := A1 xor P[0];
  B2 := B1 xor P[1];
  C2 := C1 xor P[2];
  D2 := D1 xor P[3];

  Dec(PUInt32(P), 4);

  PUInt32Array(Dest)[0] := (Rijndael_S[1, A2        and $FF]        or
                          Rijndael_S[1, D2 shr  8 and $FF] shl  8 or
                          Rijndael_S[1, C2 shr 16 and $FF] shl 16 or
                          Rijndael_S[1, B2 shr 24]         shl 24)    xor P[0];
  PUInt32Array(Dest)[1] := (Rijndael_S[1, B2        and $FF]        or
                          Rijndael_S[1, A2 shr  8 and $FF] shl  8 or
                          Rijndael_S[1, D2 shr 16 and $FF] shl 16 or
                          Rijndael_S[1, C2 shr 24]         shl 24)    xor P[1];
  PUInt32Array(Dest)[2] := (Rijndael_S[1, C2        and $FF]        or
                          Rijndael_S[1, B2 shr  8 and $FF] shl  8 or
                          Rijndael_S[1, A2 shr 16 and $FF] shl 16 or
                          Rijndael_S[1, D2 shr 24]         shl 24)    xor P[2];
  PUInt32Array(Dest)[3] := (Rijndael_S[1, D2        and $FF]        or
                          Rijndael_S[1, C2 shr  8 and $FF] shl  8 or
                          Rijndael_S[1, B2 shr 16 and $FF] shl 16 or
                          Rijndael_S[1, A2 shr 24]         shl 24)    xor P[3];
end;

{ TCipher_Square }

class function TCipher_Square.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 16;
  Result.BufferSize                  := 16;
  Result.AdditionalBufferSize        := 9 * 4 * 2 * SizeOf(UInt32);
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Square.DoInit(const Key; Size: Integer);
type
  PSquare_Key = ^TSquare_Key;
  TSquare_Key = array[0..8, 0..3] of UInt32;
var
  E, D: PSquare_Key;
  S, T, R: UInt32;
  I, J: Integer;
begin
  E := FAdditionalBuffer;
  D := FAdditionalBuffer; Inc(D);
  Move(Key, E^, Size);

  for I := 1 to 8 do
  begin
    T := E[I - 1, 3];
    T := T shr 8 or T shl 24;
    E[I, 0] := E[I - 1, 0] xor T xor 1 shl (I - 1);
    E[I, 1] := E[I - 1, 1] xor E[I, 0];
    E[I, 2] := E[I - 1, 2] xor E[I, 1];
    E[I, 3] := E[I - 1, 3] xor E[I, 2];

    D[8 - I, 0] := E[I, 0];
    D[8 - I, 1] := E[I, 1];
    D[8 - I, 2] := E[I, 2];
    D[8 - I, 3] := E[I, 3];

    for J := 0 to 3 do
    begin
      R := E[I - 1, J];
      S := Square_PHI[R and $FF];
      T := Square_PHI[R shr  8 and $FF];
      T := T shl 8 or T shr 24;
      S := S xor T;
      T := Square_PHI[R shr 16 and $FF];
      T := T shl 16 or T shr 16;
      S := S xor T;
      T := Square_PHI[R shr 24];
      T := T shl 24 or T shr 8;
      S := S xor T;
      E[I - 1, J] := S;
    end;
  end;

  D[8] := E[0];
end;

procedure TCipher_Square.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  Key: PUInt32Array;
  A, B, C, D: UInt32;
  AA, BB, CC: UInt32;
  I: Integer;
begin
  Key := FAdditionalBuffer;
  A := PUInt32Array(Source)[0] xor Key[0];
  B := PUInt32Array(Source)[1] xor Key[1];
  C := PUInt32Array(Source)[2] xor Key[2];
  D := PUInt32Array(Source)[3] xor Key[3];
  Key := @Key[4];

  for I := 0 to 6 do
  begin
    AA := Square_TE[0, A        and $FF] xor
          Square_TE[1, B        and $FF] xor
          Square_TE[2, C        and $FF] xor
          Square_TE[3, D        and $FF] xor Key[0];
    BB := Square_TE[0, A shr  8 and $FF] xor
          Square_TE[1, B shr  8 and $FF] xor
          Square_TE[2, C shr  8 and $FF] xor
          Square_TE[3, D shr  8 and $FF] xor Key[1];
    CC := Square_TE[0, A shr 16 and $FF] xor
          Square_TE[1, B shr 16 and $FF] xor
          Square_TE[2, C shr 16 and $FF] xor
          Square_TE[3, D shr 16 and $FF] xor Key[2];
    D  := Square_TE[0, A shr 24        ] xor
          Square_TE[1, B shr 24        ] xor
          Square_TE[2, C shr 24        ] xor
          Square_TE[3, D shr 24        ] xor Key[3];

    A := AA; B := BB; C := CC;

    Key := @Key[4];
  end;

  PUInt32Array(Dest)[0] := UInt32(Square_SE[A        and $FF])        xor
                         UInt32(Square_SE[B        and $FF]) shl  8 xor
                         UInt32(Square_SE[C        and $FF]) shl 16 xor
                         UInt32(Square_SE[D        and $FF]) shl 24 xor Key[0];
  PUInt32Array(Dest)[1] := UInt32(Square_SE[A shr  8 and $FF])        xor
                         UInt32(Square_SE[B shr  8 and $FF]) shl  8 xor
                         UInt32(Square_SE[C shr  8 and $FF]) shl 16 xor
                         UInt32(Square_SE[D shr  8 and $FF]) shl 24 xor Key[1];
  PUInt32Array(Dest)[2] := UInt32(Square_SE[A shr 16 and $FF])        xor
                         UInt32(Square_SE[B shr 16 and $FF]) shl  8 xor
                         UInt32(Square_SE[C shr 16 and $FF]) shl 16 xor
                         UInt32(Square_SE[D shr 16 and $FF]) shl 24 xor Key[2];
  PUInt32Array(Dest)[3] := UInt32(Square_SE[A shr 24        ])        xor
                         UInt32(Square_SE[B shr 24        ]) shl  8 xor
                         UInt32(Square_SE[C shr 24        ]) shl 16 xor
                         UInt32(Square_SE[D shr 24        ]) shl 24 xor Key[3];
end;

procedure TCipher_Square.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  Key: PUInt32Array;
  A, B, C, D: UInt32;
  AA, BB, CC: UInt32;
  I: Integer;
begin
  Key := @PUInt32Array(FAdditionalBuffer)[9 * 4];
  A := PUInt32Array(Source)[0] xor Key[0];
  B := PUInt32Array(Source)[1] xor Key[1];
  C := PUInt32Array(Source)[2] xor Key[2];
  D := PUInt32Array(Source)[3] xor Key[3];
  Key := @Key[4];

  for I := 0 to 6 do
  begin
    AA := Square_TD[0, A        and $FF] xor
          Square_TD[1, B        and $FF] xor
          Square_TD[2, C        and $FF] xor
          Square_TD[3, D        and $FF] xor Key[0];
    BB := Square_TD[0, A shr  8 and $FF] xor
          Square_TD[1, B shr  8 and $FF] xor
          Square_TD[2, C shr  8 and $FF] xor
          Square_TD[3, D shr  8 and $FF] xor Key[1];
    CC := Square_TD[0, A shr 16 and $FF] xor
          Square_TD[1, B shr 16 and $FF] xor
          Square_TD[2, C shr 16 and $FF] xor
          Square_TD[3, D shr 16 and $FF] xor Key[2];
    D  := Square_TD[0, A shr 24        ] xor
          Square_TD[1, B shr 24        ] xor
          Square_TD[2, C shr 24        ] xor
          Square_TD[3, D shr 24        ] xor Key[3];

    A := AA; B := BB; C := CC;
    Key := @Key[4];
  end;

  PUInt32Array(Dest)[0] := UInt32(Square_SD[A        and $FF])        xor
                         UInt32(Square_SD[B        and $FF]) shl  8 xor
                         UInt32(Square_SD[C        and $FF]) shl 16 xor
                         UInt32(Square_SD[D        and $FF]) shl 24 xor Key[0];
  PUInt32Array(Dest)[1] := UInt32(Square_SD[A shr  8 and $FF])        xor
                         UInt32(Square_SD[B shr  8 and $FF]) shl  8 xor
                         UInt32(Square_SD[C shr  8 and $FF]) shl 16 xor
                         UInt32(Square_SD[D shr  8 and $FF]) shl 24 xor Key[1];
  PUInt32Array(Dest)[2] := UInt32(Square_SD[A shr 16 and $FF])        xor
                         UInt32(Square_SD[B shr 16 and $FF]) shl  8 xor
                         UInt32(Square_SD[C shr 16 and $FF]) shl 16 xor
                         UInt32(Square_SD[D shr 16 and $FF]) shl 24 xor Key[2];
  PUInt32Array(Dest)[3] := UInt32(Square_SD[A shr 24        ])        xor
                         UInt32(Square_SD[B shr 24        ]) shl  8 xor
                         UInt32(Square_SD[C shr 24        ]) shl 16 xor
                         UInt32(Square_SD[D shr 24        ]) shl 24 xor Key[3];
end;

{ TCipher_SCOP }

class function TCipher_SCOP.Context: TCipherContext;
begin
  Result.KeySize                     := 48;
  Result.BlockSize                   := 4;
  Result.BufferSize                  := 32;
  Result.AdditionalBufferSize        := 384 * 4 + 3 * SizeOf(UInt32);
  Result.NeedsAdditionalBufferBackup := True;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctStream];
end;

procedure TCipher_SCOP.DoInit(const Key; Size: Integer);
var
  Init_State: packed record
    Coef: array[0..7, 0..3] of Byte;
    X: array[0..3] of UInt32;
  end;

  procedure ExpandKey;
  var
    P: PByteArray;
    I, C: Integer;
  begin
    C := 1;
    P := @Init_State;
    Move(Key, P^, Size);
    for I := Size to 47 do
      P[I] := P[I - Size] + P[I - Size + 1];
    for I := 0 to 31 do
      if P[I] = 0 then
      begin
        P[I] := C;
        Inc(C);
      end;
  end;

  procedure GP8(Data: PUInt32Array);
  var
    I, I2: Integer;
    NewX: array[0..3] of UInt32;
    X1, X2, X3, X4: UInt32;
    Y1, Y2: UInt32;
  begin
    I := 0;
    I2 := 0;
    while I < 8 do
    begin
      X1 := Init_State.X[I2] shr 16;
      X2 := X1 * X1;
      X3 := X2 * X1;
      X4 := X3 * X1;
      Y1 := Init_State.Coef[I][0] * X4 +
            Init_State.Coef[I][1] * X3 +
            Init_State.Coef[I][2] * X2 +
            Init_State.Coef[I][3] * X1 + 1;
      X1 := Init_State.X[I2] and $FFFF;
      X2 := X1 * X1;
      X3 := X2 * X1;
      X4 := X3 * X1;
      Y2 := Init_State.Coef[I + 1][0] * X4 +
            Init_State.Coef[I + 2][1] * X3 +
            Init_State.Coef[I + 3][2] * X2 +
            Init_State.Coef[I + 4][3] * X1 + 1;
      Data[I2] := Y1 shl 16 or Y2 and $FFFF;
      NewX[I2] := Y1 and $FFFF0000 or Y2 shr 16;
      Inc(I2);
      Inc(I, 2);
    end;
    Init_State.X[0] := NewX[0] shr 16 or NewX[3] shl 16;
    Init_State.X[1] := NewX[0] shl 16 or NewX[1] shr 16;
    Init_State.X[2] := NewX[1] shl 16 or NewX[2] shr 16;
    Init_State.X[3] := NewX[2] shl 16 or NewX[3] shr 16;
  end;

var
  I, J: Integer;
  T: array[0..3] of Integer;
  P: PUInt32Array;
begin
  FillChar(Init_State, SizeOf(Init_State), 0);
  FillChar(T, SizeOf(T), 0);
  P := Pointer(PByte(FAdditionalBuffer) + 12); // for Pointer Math
  ExpandKey;
  for I := 0 to 7 do
    GP8(@T);
  for I := 0 to 11 do
  begin
    for J := 0 to 7 do
      GP8(@P[I * 32 + J * 4]);
    GP8(@T);
  end;
  GP8(@T);
  I := T[3] and $7F;
  P[I + 3] := P[I + 3] or 1;
  P := FAdditionalBuffer;
  P[0] := T[3] shr 24 and $FF;
  P[1] := T[3] shr 16 and $FF;
  P[2] := T[3] shr  8 and $FF;
  ProtectBuffer(Init_State, SizeOf(Init_State));
end;

procedure TCipher_SCOP.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I, J: Byte;
  T2, T3, T1: UInt32;
  P: PUInt32Array;
  W: Integer;
begin
  P  := FAdditionalBuffer;
  I  := P[0];
  J  := P[1];
  T3 := P[2];
  for W := 0 to Size div 4 - 1 do
  begin
    T1 := P[J + 3 + 128]; Inc(J, T3);
    T2 := P[J + 3 + 128];
    PUInt32Array(Dest)[W] := PUInt32Array(Source)[W] + T1 + T2;
    T3 := T2 + P[I + 3];  Inc(I);
    P[J + 3 + 128] := T3;
    Inc(J, T2);
  end;
  P[0] := I;
  P[1] := J;
  P[2] := T3;
end;

procedure TCipher_SCOP.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I, J: Byte;
  T1, T2, T3: UInt32;
  P: PUInt32Array;
  W: Integer;
begin
  P  := FAdditionalBuffer;
  I  := P[0];
  J  := P[1];
  T3 := P[2];
  for W := 0 to Size div 4 - 1 do
  begin
    T1 := P[J + 3 + 128]; Inc(J, T3);
    T2 := P[J + 3 + 128];
    PUInt32Array(Dest)[W] := PUInt32Array(Source)[W] - T1 - T2;
    T3 := T2 + P[I + 3];
    Inc(I);
    P[J + 3 + 128] := T3;
    Inc(J, T2);
  end;
  P[0] := I;
  P[1] := J;
  P[2] := T3;
end;

{ TCipher_Sapphire }

type
  PSapphireKey = ^TSapphireKey;
  TSapphireKey = packed record
    Cards: array[0..255] of UInt32;
    Rotor: UInt32;
    Ratchet: UInt32;
    Avalanche: UInt32;
    Plain: UInt32;
    Cipher: UInt32;
  end;

class function TCipher_Sapphire.Context: TCipherContext;
begin
  Result.KeySize                     := 1024;
  Result.BlockSize                   := 1;
  Result.BufferSize                  := 32;
  Result.AdditionalBufferSize        := SizeOf(TSapphireKey);
  Result.NeedsAdditionalBufferBackup := True;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctStream];
end;

procedure TCipher_Sapphire.DoInit(const Key; Size: Integer);
var
  Sum: Byte;
  P: Integer;

  function KeyRand(Max: UInt32): Byte;
  var
    I, M: UInt32;
  begin
    Result := 0;
    if Max = 0 then
      Exit;
    I := 0;
    M := 1;

    while M < Max do
     Inc(M, M or 1);

    repeat
      Inc(Sum, TByteArray(Key)[P]);
      Inc(P);
      if P >= Size then
      begin
        P := 0;
        Inc(Sum, Size);
      end;
      Result := M and Sum;
      Inc(I);
      if I > 11 then
        Result := Result mod Max;
    until Result <= Max;
  end;

var
  I, S, T: Integer;
  SKey : PSapphireKey;
begin
  SKey := PSapphireKey(FAdditionalBuffer);
  if Size <= 0 then
  begin
    SKey.Rotor     := 1;
    SKey.Ratchet   := 3;
    SKey.Avalanche := 5;
    SKey.Plain     := 7;
    SKey.Cipher    := 11;
    for I := 0 to 255 do
      SKey.Cards[I] := 255 - I;
  end
  else
  begin
    for I := 0 to 255 do
      SKey.Cards[I] := I;
    P   := 0;
    Sum := 0;
    for I := 255 downto 1 do
    begin
      S := KeyRand(I);
      T := SKey.Cards[I];
      SKey.Cards[I] := SKey.Cards[S];
      SKey.Cards[S] := T;
    end;
    SKey.Rotor     := SKey.Cards[1];
    SKey.Ratchet   := SKey.Cards[3];
    SKey.Avalanche := SKey.Cards[5];
    SKey.Plain     := SKey.Cards[7];
    SKey.Cipher    := SKey.Cards[Sum];
  end;
end;

procedure TCipher_Sapphire.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
  I: Integer;
  SKey: TSapphireKey;
begin
  SKey := PSapphireKey(FAdditionalBuffer)^;
  for I := 0 to Size - 1 do
  begin
    SKey.Ratchet := (SKey.Ratchet + SKey.Cards[SKey.Rotor]) and $FF;
    SKey.Rotor := (SKey.Rotor + 1) and $FF;
    T := SKey.Cards[SKey.Cipher];
    SKey.Cards[SKey.Cipher]  := SKey.Cards[SKey.Ratchet];
    SKey.Cards[SKey.Ratchet] := SKey.Cards[SKey.Plain];
    SKey.Cards[SKey.Plain]   := SKey.Cards[SKey.Rotor];
    SKey.Cards[SKey.Rotor]   := T;
    SKey.Avalanche := (SKey.Avalanche + SKey.Cards[T]) and $FF;
    T := (SKey.Cards[SKey.Plain] + SKey.Cards[SKey.Cipher] + SKey.Cards[SKey.Avalanche]) and $FF;
    SKey.Plain := PByteArray(Source)[I];
    SKey.Cipher := SKey.Plain xor SKey.Cards[SKey.Cards[T]] xor
                   SKey.Cards[(SKey.Cards[SKey.Ratchet] +
                   SKey.Cards[SKey.Rotor]) and $FF];
    PByteArray(Dest)[I] := SKey.Cipher;
  end;
end;

procedure TCipher_Sapphire.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
  I: Integer;
  SKey: TSapphireKey;
begin
  SKey := PSapphireKey(FAdditionalBuffer)^;
  for I := 0 to Size - 1 do
  begin
    SKey.Ratchet := (SKey.Ratchet + SKey.Cards[SKey.Rotor]) and $FF;
    SKey.Rotor := (SKey.Rotor + 1) and $FF;
    T := SKey.Cards[SKey.Cipher];
    SKey.Cards[SKey.Cipher]  := SKey.Cards[SKey.Ratchet];
    SKey.Cards[SKey.Ratchet] := SKey.Cards[SKey.Plain];
    SKey.Cards[SKey.Plain]   := SKey.Cards[SKey.Rotor];
    SKey.Cards[SKey.Rotor]   := T;
    SKey.Avalanche := (SKey.Avalanche + SKey.Cards[T]) and $FF;
    T := (SKey.Cards[SKey.Plain] + SKey.Cards[SKey.Cipher] + SKey.Cards[SKey.Avalanche]) and $FF;
    SKey.Cipher := PByteArray(Source)[I];
    SKey.Plain := SKey.Cipher xor SKey.Cards[SKey.Cards[T]] xor
                  SKey.Cards[(SKey.Cards[SKey.Ratchet] +
                  SKey.Cards[SKey.Rotor]) and $FF];
    PByteArray(Dest)[I] := SKey.Plain;
  end;
end;

{ TCipher_1DES }

procedure DES_Func(Source, Dest, Key: PUInt32Array);
var
  L, R, X, Y, I: UInt32;
begin
  L := SwapUInt32(Source[0]);
  R := SwapUInt32(Source[1]);

  X := (L shr  4 xor R) and $0F0F0F0F; R := R xor X; L := L xor X shl  4;
  X := (L shr 16 xor R) and $0000FFFF; R := R xor X; L := L xor X shl 16;
  X := (R shr  2 xor L) and $33333333; L := L xor X; R := R xor X shl  2;
  X := (R shr  8 xor L) and $00FF00FF; L := L xor X; R := R xor X shl  8;

  R := R shl 1 or R shr 31;
  X := (L xor R) and $AAAAAAAA;
  R := R xor X;
  L := L xor X;
  L := L shl 1 or L shr 31;

  for I := 0 to 7 do
  begin
    X := (R shl 28 or R shr 4) xor Key[0];
    Y := R xor Key[1];
    L := L xor (DES_Data[0, X        and $3F] or DES_Data[1, X shr  8 and $3F] or
                DES_Data[2, X shr 16 and $3F] or DES_Data[3, X shr 24 and $3F] or
                DES_Data[4, Y        and $3F] or DES_Data[5, Y shr  8 and $3F] or
                DES_Data[6, Y shr 16 and $3F] or DES_Data[7, Y shr 24 and $3F]);

    X := (L shl 28 or L shr 4) xor Key[2];
    Y := L xor Key[3];
    R := R xor (DES_Data[0, X        and $3F] or DES_Data[1, X shr  8 and $3F] or
                DES_Data[2, X shr 16 and $3F] or DES_Data[3, X shr 24 and $3F] or
                DES_Data[4, Y        and $3F] or DES_Data[5, Y shr  8 and $3F] or
                DES_Data[6, Y shr 16 and $3F] or DES_Data[7, Y shr 24 and $3F]);
    Key := @Key[4];
  end;

  R := R shl 31 or R shr 1;
  X := (L xor R) and $AAAAAAAA;
  R := R xor X;
  L := L xor X;
  L := L shl 31 or L shr 1;

  X := (L shr  8 xor R) and $00FF00FF; R := R xor X; L := L xor X shl  8;
  X := (L shr  2 xor R) and $33333333; R := R xor X; L := L xor X shl  2;
  X := (R shr 16 xor L) and $0000FFFF; L := L xor X; R := R xor X shl 16;
  X := (R shr  4 xor L) and $0F0F0F0F; L := L xor X; R := R xor X shl  4;

  Dest[0] := SwapUInt32(R);
  Dest[1] := SwapUInt32(L);
end;

class function TCipher_1DES.Context: TCipherContext;
begin
  Result.KeySize                     := 8;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 32 * 4 * 2;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_1DES.DoInitKey(const Data: array of Byte; Key: PUInt32Array; Reverse: Boolean);
const
  ROT: array[0..15] of Byte = (1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28);
var
  I, J, L, M, N: UInt32;
  PC_M, PC_R: array[0..55] of Byte;
  K: array[0..31] of UInt32;
begin
  FillChar(K, SizeOf(K), 0);
  for I := 0 to 55 do
    if Data[DES_PC1[I] shr 3] and ($80 shr (DES_PC1[I] and $07)) <> 0 then
      PC_M[I] := 1
    else
      PC_M[I] := 0;
  for I := 0 to 15 do
  begin
    if Reverse then
      M := (15 - I) shl 1
    else
      M := I shl 1;
    N := M + 1;
    for J := 0 to 27 do
    begin
      L := J + ROT[I];
      if L < 28 then
        PC_R[J] := PC_M[L]
      else
        PC_R[J] := PC_M[L - 28];
    end;
    for J := 28 to 55 do
    begin
      L := J + ROT[I];
      if L < 56 then
        PC_R[J] := PC_M[L]
      else
        PC_R[J] := PC_M[L - 28];
    end;
    L := $1000000;
    for J := 0 to 23 do
    begin
      L := L shr 1;
      if PC_R[DES_PC2[J     ]] <> 0 then
        K[M] := K[M] or L;
      if PC_R[DES_PC2[J + 24]] <> 0 then
        K[N] := K[N] or L;
    end;
  end;
  for I := 0 to 15 do
  begin
    M := I shl 1;
    N := M + 1;
    Key[0] := K[M] and $00FC0000 shl  6 or
              K[M] and $00000FC0 shl 10 or
              K[N] and $00FC0000 shr 10 or
              K[N] and $00000FC0 shr  6;
    Key[1] := K[M] and $0003F000 shl 12 or
              K[M] and $0000003F shl 16 or
              K[N] and $0003F000 shr  4 or
              K[N] and $0000003F;
    Key := @Key[2];
  end;
  ProtectBuffer(K, SizeOf(K));
  ProtectBuffer(PC_M, SizeOf(PC_M));
  ProtectBuffer(PC_R, SizeOf(PC_R));
end;

procedure TCipher_1DES.DoInit(const Key; Size: Integer);
var
  K: array[0..7] of Byte;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  DoInitKey(K, FAdditionalBuffer, False);
  DoInitKey(K, @PUInt32Array(FAdditionalBuffer)[32], True);
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_1DES.DoEncode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  DES_Func(Source, Dest, FAdditionalBuffer);
end;

procedure TCipher_1DES.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[32]);
end;

{ TCipher_2DES }

class function TCipher_2DES.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 32 * 4 * 2 * 2;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_2DES.DoInit(const Key; Size: Integer);
var
  K: array[0..15] of Byte;
  P: PUInt32Array;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  P := FAdditionalBuffer;
  DoInitKey(K[0], @P[ 0], False);
  DoInitKey(K[8], @P[32], True);
  DoInitKey(K[0], @P[64], True);
  DoInitKey(K[8], @P[96], False);
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_2DES.DoEncode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  DES_Func(Source, Dest, FAdditionalBuffer);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[32]);
  DES_Func(Source, Dest, FAdditionalBuffer);
end;

procedure TCipher_2DES.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[64]);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[96]);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[64]);
end;

{ TCipher_3DES }

class function TCipher_3DES.Context: TCipherContext;
begin
  Result.KeySize                     := 24;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 32 * 4 * 2 * 3;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_3DES.DoInit(const Key; Size: Integer);
var
  K: array[0..23] of Byte;
  P: PUInt32Array;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  P := FAdditionalBuffer;
  DoInitKey(K[ 0], @P[  0], False);
  DoInitKey(K[ 8], @P[ 32], True);
  DoInitKey(K[16], @P[ 64], False);
  DoInitKey(K[16], @P[ 96], True);
  DoInitKey(K[ 8], @P[128], False);
  DoInitKey(K[ 0], @P[160], True);
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_3DES.DoEncode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[ 0]);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[32]);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[64]);
end;

procedure TCipher_3DES.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[96]);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[128]);
  DES_Func(Source, Dest, @PUInt32Array(FAdditionalBuffer)[160]);
end;

{ TCipher_2DDES }

class function TCipher_2DDES.Context: TCipherContext;
begin
  Result            := inherited Context;
  Result.BlockSize  := 16;
  Result.BufferSize := 16;
  Result.MinRounds  := 1;
  Result.MaxRounds  := 1;
  Result.CipherType := [ctSymmetric, ctBlock];
end;

procedure TCipher_2DDES.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
begin
  Assert(Size = Context.BlockSize);

  DES_Func(@PUInt32Array(Source)[0], @PUInt32Array(Dest)[0], FAdditionalBuffer);
  DES_Func(@PUInt32Array(Source)[2], @PUInt32Array(Dest)[2], FAdditionalBuffer);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[32]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[32]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], FAdditionalBuffer);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], FAdditionalBuffer);
end;

procedure TCipher_2DDES.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
begin
  Assert(Size = Context.BlockSize);

  DES_Func(@PUInt32Array(Source)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[64]);
  DES_Func(@PUInt32Array(Source)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[64]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[96]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[96]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[64]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[64]);
end;

{ TCipher_3DDES }

class function TCipher_3DDES.Context: TCipherContext;
begin
  Result            := inherited Context;
  Result.BlockSize  := 16;
  Result.BufferSize := 16;
  Result.MinRounds  := 1;
  Result.MaxRounds  := 1;
  Result.CipherType := [ctSymmetric, ctBlock];
end;

procedure TCipher_3DDES.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
begin
  Assert(Size = Context.BlockSize);

  DES_Func(@PUInt32Array(Source)[0], @PUInt32Array(Dest)[0], FAdditionalBuffer);
  DES_Func(@PUInt32Array(Source)[2], @PUInt32Array(Dest)[2], FAdditionalBuffer);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[32]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[32]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[64]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[64]);
end;

procedure TCipher_3DDES.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
begin
  Assert(Size = Context.BlockSize);

  DES_Func(@PUInt32Array(Source)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[96]);
  DES_Func(@PUInt32Array(Source)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[96]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[128]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[128]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[160]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[160]);
end;

{ TCipher_3TDES }

class function TCipher_3TDES.Context: TCipherContext;
begin
  Result            := inherited Context;
  Result.BlockSize  := 24;
  Result.BufferSize := 24;
  Result.MinRounds  := 1;
  Result.MaxRounds  := 1;
  Result.CipherType := [ctSymmetric, ctBlock];
end;

procedure TCipher_3TDES.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
begin
  Assert(Size = Context.BlockSize);

  DES_Func(@PUInt32Array(Source)[0], @PUInt32Array(Dest)[0], FAdditionalBuffer);
  DES_Func(@PUInt32Array(Source)[2], @PUInt32Array(Dest)[2], FAdditionalBuffer);
  DES_Func(@PUInt32Array(Source)[4], @PUInt32Array(Dest)[4], FAdditionalBuffer);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  T := PUInt32Array(Dest)[3];
  PUInt32Array(Dest)[3] := PUInt32Array(Dest)[4];
  PUInt32Array(Dest)[4] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[32]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[32]);
  DES_Func(@PUInt32Array(Dest)[4], @PUInt32Array(Dest)[4], @PUInt32Array(FAdditionalBuffer)[32]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  T := PUInt32Array(Dest)[3];
  PUInt32Array(Dest)[3] := PUInt32Array(Dest)[4];
  PUInt32Array(Dest)[4] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[64]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[64]);
  DES_Func(@PUInt32Array(Dest)[4], @PUInt32Array(Dest)[4], @PUInt32Array(FAdditionalBuffer)[64]);
end;

procedure TCipher_3TDES.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  T: UInt32;
begin
  Assert(Size = Context.BlockSize);

  DES_Func(@PUInt32Array(Source)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[96]);
  DES_Func(@PUInt32Array(Source)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[96]);
  DES_Func(@PUInt32Array(Source)[4], @PUInt32Array(Dest)[4], @PUInt32Array(FAdditionalBuffer)[96]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  T := PUInt32Array(Dest)[3];
  PUInt32Array(Dest)[3] := PUInt32Array(Dest)[4];
  PUInt32Array(Dest)[4] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[128]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[128]);
  DES_Func(@PUInt32Array(Dest)[4], @PUInt32Array(Dest)[4], @PUInt32Array(FAdditionalBuffer)[128]);
  T := PUInt32Array(Dest)[1];
  PUInt32Array(Dest)[1] := PUInt32Array(Dest)[2];
  PUInt32Array(Dest)[2] := T;
  T := PUInt32Array(Dest)[3];
  PUInt32Array(Dest)[3] := PUInt32Array(Dest)[4];
  PUInt32Array(Dest)[4] := T;
  DES_Func(@PUInt32Array(Dest)[0], @PUInt32Array(Dest)[0], @PUInt32Array(FAdditionalBuffer)[160]);
  DES_Func(@PUInt32Array(Dest)[2], @PUInt32Array(Dest)[2], @PUInt32Array(FAdditionalBuffer)[160]);
  DES_Func(@PUInt32Array(Dest)[4], @PUInt32Array(Dest)[4], @PUInt32Array(FAdditionalBuffer)[160]);
end;

{ TCipher_3Way }

type
  P3Way_Key = ^T3Way_Key;
  T3Way_Key = packed record
    E_Key: array[0..2] of UInt32;
    E_Data: array[0..11] of UInt32;
    D_Key: array[0..2] of UInt32;
    D_Data: array[0..11] of UInt32;
  end;

class function TCipher_3Way.Context: TCipherContext;
begin
  Result.KeySize                     := 12;
  Result.BlockSize                   := 12;
  Result.BufferSize                  := 12;
  Result.AdditionalBufferSize        := SizeOf(T3Way_Key);
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_3Way.DoInit(const Key; Size: Integer);

  procedure RANDGenerate(Start: UInt32; var P: array of UInt32);
  var
    I: Integer;
  begin
    for I := 0 to 11 do
    begin
      P[I] := Start;
      Start := Start shl 1;
      if Start and $10000 <> 0 then
        Start := Start xor $11011;
    end;
  end;

var
  A0, A1, A2: UInt32;
  B0, B1, B2: UInt32;
  P3WayKey: P3Way_Key;
begin
  P3WayKey := P3Way_Key(FAdditionalBuffer);

  Move(Key, P3WayKey.E_Key, Size);
  Move(Key, P3WayKey.D_Key, Size);
  RANDGenerate($0B0B, P3WayKey.E_Data);
  RANDGenerate($B1B1, P3WayKey.D_Data);
  A0 := P3WayKey.D_Key[0];
  A1 := P3WayKey.D_Key[1];
  A2 := P3WayKey.D_Key[2];
  B0 := A0 xor A0 shr 16 xor A1 shl 16 xor A1 shr 16 xor A2 shl 16 xor
               A1 shr 24 xor A2 shl  8 xor A2 shr  8 xor A0 shl 24 xor
               A2 shr 16 xor A0 shl 16 xor A2 shr 24 xor A0 shl  8;
  B1 := A1 xor A1 shr 16 xor A2 shl 16 xor A2 shr 16 xor A0 shl 16 xor
               A2 shr 24 xor A0 shl  8 xor A0 shr  8 xor A1 shl 24 xor
               A0 shr 16 xor A1 shl 16 xor A0 shr 24 xor A1 shl  8;
  B2 := A2 xor A2 shr 16 xor A0 shl 16 xor A0 shr 16 xor A1 shl 16 xor
               A0 shr 24 xor A1 shl  8 xor A1 shr  8 xor A2 shl 24 xor
               A1 shr 16 xor A2 shl 16 xor A1 shr 24 xor A2 shl  8;
  P3WayKey.D_Key[2] := ReverseBits(B0);
  P3WayKey.D_Key[1] := ReverseBits(B1);
  P3WayKey.D_Key[0] := ReverseBits(B2);
end;

procedure TCipher_3Way.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  A0, A1, A2: UInt32;
  B0, B1, B2: UInt32;
  K0, K1, K2: UInt32;
  E: PUInt32;
  P3WayKey: P3Way_Key;
begin
  Assert(Size = Context.BlockSize);
  P3WayKey := P3Way_Key(FAdditionalBuffer);

  K0 := P3WayKey.E_Key[0];
  K1 := P3WayKey.E_Key[1];
  K2 := P3WayKey.E_Key[2];
  E  := @P3WayKey.E_Data;

  A0 := PUInt32Array(Source)[0];
  A1 := PUInt32Array(Source)[1];
  A2 := PUInt32Array(Source)[2];
  for I := 0 to 10 do
  begin
    A0 := A0 xor K0 xor E^ shl 16;
    A1 := A1 xor K1;
    A2 := A2 xor K2 xor E^;
    Inc(E);

    B0 := A0 xor A0 shr 16 xor A1 shl 16 xor A1 shr 16 xor A2 shl 16 xor
                 A1 shr 24 xor A2 shl  8 xor A2 shr  8 xor A0 shl 24 xor
                 A2 shr 16 xor A0 shl 16 xor A2 shr 24 xor A0 shl  8;
    B1 := A1 xor A1 shr 16 xor A2 shl 16 xor A2 shr 16 xor A0 shl 16 xor
                 A2 shr 24 xor A0 shl  8 xor A0 shr  8 xor A1 shl 24 xor
                 A0 shr 16 xor A1 shl 16 xor A0 shr 24 xor A1 shl  8;
    B2 := A2 xor A2 shr 16 xor A0 shl 16 xor A0 shr 16 xor A1 shl 16 xor
                 A0 shr 24 xor A1 shl  8 xor A1 shr  8 xor A2 shl 24 xor
                 A1 shr 16 xor A2 shl 16 xor A1 shr 24 xor A2 shl  8;
    B0 := B0 shr 10 or B0 shl 22;
    B2 := B2 shl  1 or B2 shr 31;
    A0 := B0 xor (B1 or not B2);
    A1 := B1 xor (B2 or not B0);
    A2 := B2 xor (B0 or not B1);
    A0 := A0 shl  1 or A0 shr 31;
    A2 := A2 shr 10 or A2 shl 22;
  end;
  A0 := A0 xor K0 xor E^ shl 16;
  A1 := A1 xor K1;
  A2 := A2 xor K2 xor E^;
  PUInt32Array(Dest)[0] := A0 xor A0 shr 16 xor A1 shl 16 xor A1 shr 16 xor A2 shl 16 xor
                                A1 shr 24 xor A2 shl  8 xor A2 shr  8 xor A0 shl 24 xor
                                A2 shr 16 xor A0 shl 16 xor A2 shr 24 xor A0 shl  8;
  PUInt32Array(Dest)[1] := A1 xor A1 shr 16 xor A2 shl 16 xor A2 shr 16 xor A0 shl 16 xor
                                A2 shr 24 xor A0 shl  8 xor A0 shr  8 xor A1 shl 24 xor
                                A0 shr 16 xor A1 shl 16 xor A0 shr 24 xor A1 shl  8;
  PUInt32Array(Dest)[2] := A2 xor A2 shr 16 xor A0 shl 16 xor A0 shr 16 xor A1 shl 16 xor
                                A0 shr 24 xor A1 shl  8 xor A1 shr  8 xor A2 shl 24 xor
                                A1 shr 16 xor A2 shl 16 xor A1 shr 24 xor A2 shl  8;
end;

procedure TCipher_3Way.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  A0, A1, A2: UInt32;
  B0, B1, B2: UInt32;
  K0, K1, K2: UInt32;
  E: PUInt32;
  P3WayKey: P3Way_Key;
begin
  Assert(Size = Context.BlockSize);
  P3WayKey := P3Way_Key(FAdditionalBuffer);

  K0 := P3WayKey.D_Key[0];
  K1 := P3WayKey.D_Key[1];
  K2 := P3WayKey.D_Key[2];
  E  := @P3WayKey.D_Data;

  A0 := ReverseBits(PUInt32Array(Source)[2]);
  A1 := ReverseBits(PUInt32Array(Source)[1]);
  A2 := ReverseBits(PUInt32Array(Source)[0]);
  for I := 0 to 10 do
  begin
    A0 := A0 xor K0 xor E^ shl 16;
    A1 := A1 xor K1;
    A2 := A2 xor K2 xor E^;
    Inc(E);

    B0 := A0 xor A0 shr 16 xor A1 shl 16 xor A1 shr 16 xor A2 shl 16 xor
                 A1 shr 24 xor A2 shl  8 xor A2 shr  8 xor A0 shl 24 xor
                 A2 shr 16 xor A0 shl 16 xor A2 shr 24 xor A0 shl  8;
    B1 := A1 xor A1 shr 16 xor A2 shl 16 xor A2 shr 16 xor A0 shl 16 xor
                 A2 shr 24 xor A0 shl  8 xor A0 shr  8 xor A1 shl 24 xor
                 A0 shr 16 xor A1 shl 16 xor A0 shr 24 xor A1 shl  8;
    B2 := A2 xor A2 shr 16 xor A0 shl 16 xor A0 shr 16 xor A1 shl 16 xor
                 A0 shr 24 xor A1 shl  8 xor A1 shr  8 xor A2 shl 24 xor
                 A1 shr 16 xor A2 shl 16 xor A1 shr 24 xor A2 shl  8;
    B0 := B0 shr 10 or B0 shl 22;
    B2 := B2 shl  1 or B2 shr 31;
    A0 := B0 xor (B1 or not B2);
    A1 := B1 xor (B2 or not B0);
    A2 := B2 xor (B0 or not B1);
    A0 := A0 shl  1 or A0 shr 31;
    A2 := A2 shr 10 or A2 shl 22;
  end;
  A0 := A0 xor K0 xor E^ shl 16;
  A1 := A1 xor K1;
  A2 := A2 xor K2 xor E^;
  B0 := A0 xor A0 shr 16 xor A1 shl 16 xor A1 shr 16 xor A2 shl 16 xor
               A1 shr 24 xor A2 shl  8 xor A2 shr  8 xor A0 shl 24 xor
               A2 shr 16 xor A0 shl 16 xor A2 shr 24 xor A0 shl  8;
  B1 := A1 xor A1 shr 16 xor A2 shl 16 xor A2 shr 16 xor A0 shl 16 xor
               A2 shr 24 xor A0 shl  8 xor A0 shr  8 xor A1 shl 24 xor
               A0 shr 16 xor A1 shl 16 xor A0 shr 24 xor A1 shl  8;
  B2 := A2 xor A2 shr 16 xor A0 shl 16 xor A0 shr 16 xor A1 shl 16 xor
               A0 shr 24 xor A1 shl  8 xor A1 shr  8 xor A2 shl 24 xor
               A1 shr 16 xor A2 shl 16 xor A1 shr 24 xor A2 shl  8;

  PUInt32Array(Dest)[2] := ReverseBits(B0);
  PUInt32Array(Dest)[1] := ReverseBits(B1);
  PUInt32Array(Dest)[0] := ReverseBits(B2);
end;

{ TCipher_Cast128 }

class function TCipher_Cast128.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 128;
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 256;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Cast128.SetRounds(Value: Integer);
begin
  if Value <> FRounds then
  begin
    if not (FState in [csNew, csInitialized, csDone]) then
      Done;
    if (FState <> csNew) and (Value <= 0) then
      Value := 16;
    FRounds := Value;
  end;
end;

procedure TCipher_Cast128.DoInit(const Key; Size: Integer);
var
  Z, X, T: array[0..3] of UInt32;
  K: PUInt32Array;
  I: UInt32;
begin
  if FRounds <= 0 then
  begin
    if Size <= 10 then
      FRounds := 12
    else
      FRounds := 16;
  end;
  K := FAdditionalBuffer;
  FillChar(X, SizeOf(X), 0);
  Move(Key, X, Size);
  SwapUInt32Buffer(X, X, 4);
  I := 0;
  while I < 32 do
  begin
    if I and 4 = 0 then
    begin
      Z[0] := X[0] xor Cast128_Key[0, X[3] shr 16 and $FF] xor
                       Cast128_Key[1, X[3] and $FF] xor
                       Cast128_Key[2, X[3] shr 24] xor
                       Cast128_Key[3, X[3] shr  8 and $FF] xor
                       Cast128_Key[2, X[2] shr 24];
      T[0] := Z[0];
      Z[1] := X[2] xor Cast128_Key[0, Z[0] shr 24] xor
                       Cast128_Key[1, Z[0] shr  8 and $FF] xor
                       Cast128_Key[2, Z[0] shr 16 and $FF] xor
                       Cast128_Key[3, Z[0] and $FF] xor
                       Cast128_Key[3, X[2] shr  8 and $FF];
      T[1] := Z[1];
      Z[2] := X[3] xor Cast128_Key[0, Z[1] and $FF] xor
                       Cast128_Key[1, Z[1] shr  8 and $FF] xor
                       Cast128_Key[2, Z[1] shr 16 and $FF] xor
                       Cast128_Key[3, Z[1] shr 24] xor
                       Cast128_Key[0, X[2] shr 16 and $FF];
      T[2] := Z[2];
      Z[3] := X[1] xor Cast128_Key[0, Z[2] shr  8 and $FF] xor
                       Cast128_Key[1, Z[2] shr 16 and $FF] xor
                       Cast128_Key[2, Z[2] and $FF] xor
                       Cast128_Key[3, Z[2] shr 24] xor
                       Cast128_Key[1, X[2] and $FF];
      T[3] := Z[3];
    end
    else
    begin
      X[0] := Z[2] xor Cast128_Key[0, Z[1] shr 16 and $FF] xor
                       Cast128_Key[1, Z[1] and $FF] xor
                       Cast128_Key[2, Z[1] shr 24] xor
                       Cast128_Key[3, Z[1] shr  8 and $FF] xor
                       Cast128_Key[2, Z[0] shr 24];
      T[0] := X[0];
      X[1] := Z[0] xor Cast128_Key[0, X[0] shr 24] xor
                       Cast128_Key[1, X[0] shr  8 and $FF] xor
                       Cast128_Key[2, X[0] shr 16 and $FF] xor
                       Cast128_Key[3, X[0] and $FF] xor
                       Cast128_Key[3, Z[0] shr  8 and $FF];
      T[1] := X[1];
      X[2] := Z[1] xor Cast128_Key[0, X[1] and $FF] xor
                       Cast128_Key[1, X[1] shr  8 and $FF] xor
                       Cast128_Key[2, X[1] shr 16 and $FF] xor
                       Cast128_Key[3, X[1] shr 24] xor
                       Cast128_Key[0, Z[0] shr 16 and $FF];
      T[2] := X[2];
      X[3] := Z[3] xor Cast128_Key[0, X[2] shr  8 and $FF] xor
                       Cast128_Key[1, X[2] shr 16 and $FF] xor
                       Cast128_Key[2, X[2] and $FF] xor
                       Cast128_Key[3, X[2] shr 24] xor
                       Cast128_Key[1, Z[0] and $FF];
      T[3] := X[3];
    end;
    case I and 12 of
      0,12:
        begin
          K[I + 0] := Cast128_Key[0, T[2] shr 24] xor
                      Cast128_Key[1, T[2] shr 16 and $FF] xor
                      Cast128_Key[2, T[1] and $FF] xor
                      Cast128_Key[3, T[1] shr  8 and $FF];
          K[I + 1] := Cast128_Key[0, T[2] shr  8 and $FF] xor
                      Cast128_Key[1, T[2] and $FF] xor
                      Cast128_Key[2, T[1] shr 16 and $FF] xor
                      Cast128_Key[3, T[1] shr 24];
          K[I + 2] := Cast128_Key[0, T[3] shr 24] xor
                      Cast128_Key[1, T[3] shr 16 and $FF] xor
                      Cast128_Key[2, T[0] and $FF] xor
                      Cast128_Key[3, T[0] shr  8 and $FF];
          K[I + 3] := Cast128_Key[0, T[3] shr  8 and $FF] xor
                      Cast128_Key[1, T[3] and $FF] xor
                      Cast128_Key[2, T[0] shr 16 and $FF] xor
                      Cast128_Key[3, T[0] shr 24];
        end;
      4,8:
        begin
          K[I + 0] := Cast128_Key[0, T[0] and $FF] xor
                      Cast128_Key[1, T[0] shr  8 and $FF] xor
                      Cast128_Key[2, T[3] shr 24] xor
                      Cast128_Key[3, T[3] shr 16 and $FF];
          K[I + 1] := Cast128_Key[0, T[0] shr 16 and $FF] xor
                      Cast128_Key[1, T[0] shr 24] xor
                      Cast128_Key[2, T[3] shr  8 and $FF] xor
                      Cast128_Key[3, T[3] and $FF];
          K[I + 2] := Cast128_Key[0, T[1] and $FF] xor
                      Cast128_Key[1, T[1] shr  8 and $FF] xor
                      Cast128_Key[2, T[2] shr 24] xor
                      Cast128_Key[3, T[2] shr 16 and $FF];
          K[I + 3] := Cast128_Key[0, T[1] shr 16 and $FF] xor
                      Cast128_Key[1, T[1] shr 24] xor
                      Cast128_Key[2, T[2] shr  8 and $FF] xor
                      Cast128_Key[3, T[2] and $FF];
        end;
    end;
    case I and 12 of
      0: begin
           K[I + 0] := K[I + 0] xor Cast128_Key[0, Z[0] shr  8 and $FF];
           K[I + 1] := K[I + 1] xor Cast128_Key[1, Z[1] shr  8 and $FF];
           K[I + 2] := K[I + 2] xor Cast128_Key[2, Z[2] shr 16 and $FF];
           K[I + 3] := K[I + 3] xor Cast128_Key[3, Z[3] shr 24];
         end;
      4: begin
           K[I + 0] := K[I + 0] xor Cast128_Key[0, X[2] shr 24];
           K[I + 1] := K[I + 1] xor Cast128_Key[1, X[3] shr 16 and $FF];
           K[I + 2] := K[I + 2] xor Cast128_Key[2, X[0] and $FF];
           K[I + 3] := K[I + 3] xor Cast128_Key[3, X[1] and $FF];
         end;
      8: begin
           K[I + 0] := K[I + 0] xor Cast128_Key[0, Z[2] shr 16 and $FF];
           K[I + 1] := K[I + 1] xor Cast128_Key[1, Z[3] shr 24];
           K[I + 2] := K[I + 2] xor Cast128_Key[2, Z[0] shr  8 and $FF];
           K[I + 3] := K[I + 3] xor Cast128_Key[3, Z[1] shr  8 and $FF];
         end;
     12: begin
          K[I + 0] := K[I + 0] xor Cast128_Key[0, X[0] and $FF];
          K[I + 1] := K[I + 1] xor Cast128_Key[1, X[1] and $FF];
          K[I + 2] := K[I + 2] xor Cast128_Key[2, X[2] shr 24];
          K[I + 3] := K[I + 3] xor Cast128_Key[3, X[3] shr 16 and $FF];
        end;
    end;
    if I >= 16 then
    begin
      K[I + 0] := K[I + 0] and $1F;
      K[I + 1] := K[I + 1] and $1F;
      K[I + 2] := K[I + 2] and $1F;
      K[I + 3] := K[I + 3] and $1F;
    end;
    Inc(I, 4);
  end;
  ProtectBuffer(X, SizeOf(X));
  ProtectBuffer(Z, SizeOf(Z));
  ProtectBuffer(T, SizeOf(T));
end;

procedure TCipher_Cast128.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  T, I, A, B: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  A := SwapUInt32(PUInt32Array(Source)[0]);
  B := SwapUInt32(PUInt32Array(Source)[1]);
  for I := 0 to 2 do
  begin
    T := K[0] + B;
    T := T shl K[16] or T shr (32 - K[16]);
    A := A xor (Cast128_Data[0, T shr 24] xor
                Cast128_Data[1, T shr 16 and $FF] -
                Cast128_Data[2, T shr  8 and $FF] +
                Cast128_Data[3, T and $FF]);
    T := K[1] xor A;
    T := T shl K[17] or T shr (32 - K[17]);
    B := B xor (Cast128_Data[0, T shr 24] -
                Cast128_Data[1, T shr 16 and $FF] +
                Cast128_Data[2, T shr  8 and $FF] xor
                Cast128_Data[3, T and $FF]);
    T := K[2] - B;
    T := T shl K[18] or T shr (32 - K[18]);
    A := A xor (Cast128_Data[0, T shr 24] +
                Cast128_Data[1, T shr 16 and $FF] xor
                Cast128_Data[2, T shr  8 and $FF] -
                Cast128_Data[3, T and $FF]);
    T := K[3] + A;
    T := T shl K[19] or T shr (32 - K[19]);
    B := B xor (Cast128_Data[0, T shr 24] xor
                Cast128_Data[1, T shr 16 and $FF] -
                Cast128_Data[2, T shr  8 and $FF] +
                Cast128_Data[3, T and $FF]);
    if I = 2 then
      Break;
    T := K[4] xor B;
    T := T shl K[20] or T shr (32 - K[20]);
    A := A xor (Cast128_Data[0, T shr 24] -
                Cast128_Data[1, T shr 16 and $FF] +
                Cast128_Data[2, T shr  8 and $FF] xor
                Cast128_Data[3, T and $FF]);
    T := K[5] - A;
    T := T shl K[21] or T shr (32 - K[21]);
    B := B xor (Cast128_Data[0, T shr 24] +
                Cast128_Data[1, T shr 16 and $FF] xor
                Cast128_Data[2, T shr  8 and $FF] -
                Cast128_Data[3, T and $FF]);
    if (I = 1) and (FRounds <= 12) then
      Break;
    K := @K[6];
  end;
  PUInt32Array(Dest)[0] := SwapUInt32(B);
  PUInt32Array(Dest)[1] := SwapUInt32(A);
end;

procedure TCipher_Cast128.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  T, I, A, B: UInt32;
  K: PUInt32Array;
  JumpStart: Boolean;
begin
  Assert(Size = Context.BlockSize);
  JumpStart := False;

  K := @PUInt32Array(FAdditionalBuffer)[12];
  B := SwapUInt32(PUInt32Array(Source)[0]);
  A := SwapUInt32(PUInt32Array(Source)[1]);
  I := 2;

  if FRounds <= 12 then
    Dec(PUInt32(K), 6)
  else
    JumpStart := True;

  while I > 0 do
  begin
    if not JumpStart then
    begin
      Dec(I);
      T := K[5] - A;
      T := T shl K[21] or T shr (32 - K[21]);
      B := B xor (Cast128_Data[0, T shr 24] +
                  Cast128_Data[1, T shr 16 and $FF] xor
                  Cast128_Data[2, T shr  8 and $FF] -
                  Cast128_Data[3, T and $FF]);
      T := K[4] xor B;
      T := T shl K[20] or T shr (32 - K[20]);
      A := A xor (Cast128_Data[0, T shr 24] -
                  Cast128_Data[1, T shr 16 and $FF] +
                  Cast128_Data[2, T shr  8 and $FF] xor
                  Cast128_Data[3, T and $FF]);
    end
    else
      JumpStart := False;

    T := K[3] + A;
    T := T shl K[19] or T shr (32 - K[19]);
    B := B xor (Cast128_Data[0, T shr 24] xor
                Cast128_Data[1, T shr 16 and $FF] -
                Cast128_Data[2, T shr  8 and $FF] +
                Cast128_Data[3, T and $FF]);
    T := K[2] - B;
    T := T shl K[18] or T shr (32 - K[18]);
    A := A xor (Cast128_Data[0, T shr 24] +
                Cast128_Data[1, T shr 16 and $FF] xor
                Cast128_Data[2, T shr  8 and $FF] -
                Cast128_Data[3, T and $FF]);
    T := K[1] xor A;
    T := T shl K[17] or T shr (32 - K[17]);
    B := B xor (Cast128_Data[0, T shr 24] -
                Cast128_Data[1, T shr 16 and $FF] +
                Cast128_Data[2, T shr  8 and $FF] xor
                Cast128_Data[3, T and $FF]);
    T := K[0] + B;
    T := T shl K[16] or T shr (32 - K[16]);
    A := A xor (Cast128_Data[0, T shr 24] xor
                Cast128_Data[1, T shr 16 and $FF] -
                Cast128_Data[2, T shr  8 and $FF] +
                Cast128_Data[3, T and $FF]);
    Dec(PUInt32(K), 6);
  end;

  PUInt32Array(Dest)[0] := SwapUInt32(A);
  PUInt32Array(Dest)[1] := SwapUInt32(B);
end;

{ TCipher_Gost }

class function TCipher_Gost.Context: TCipherContext;
begin
  Result.KeySize                     := 32;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 32;
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Gost.DoInit(const Key; Size: Integer);
begin
  Move(Key, FAdditionalBuffer^, Size);
end;

procedure TCipher_Gost.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I, A, B, T: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  A := PUInt32Array(Source)[0];
  B := PUInt32Array(Source)[1];

  for I := 0 to 11 do
  begin
    if I and 3 = 0 then
      K := FAdditionalBuffer;
    T := A + K[0];
    B := B xor Gost_Data[0, T        and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24        ];
    T := B + K[1];
    A := A xor Gost_Data[0, T        and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24        ];
    K := @K[2];
  end;

  K := @PUInt32Array(FAdditionalBuffer)[6];

  for I := 0 to 3 do
  begin
    T := A + K[1];
    B := B xor Gost_Data[0, T        and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24        ];
    T := B + K[0];
    A := A xor Gost_Data[0, T        and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24        ];
    Dec(PUInt32(K), 2);
  end;

  PUInt32Array(Dest)[0] := B;
  PUInt32Array(Dest)[1] := A;
end;

procedure TCipher_Gost.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I, A, B, T: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  A := PUInt32Array(Source)[0];
  B := PUInt32Array(Source)[1];
  K := FAdditionalBuffer;

  for I := 0 to 3 do
  begin
    T := A + K[0];
    B := B xor Gost_Data[0, T and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24];
    T := B + K[1];
    A := A xor Gost_Data[0, T and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24];
    K := @K[2];
  end;

  for I := 0 to 11 do
  begin
    if I and 3 = 0 then
      K := @PUInt32Array(FAdditionalBuffer)[6];
    T := A + K[1];
    B := B xor Gost_Data[0, T and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24];
    T := B + K[0];
    A := A xor Gost_Data[0, T and $FF] xor
               Gost_Data[1, T shr  8 and $FF] xor
               Gost_Data[2, T shr 16 and $FF] xor
               Gost_Data[3, T shr 24];
    Dec(PUInt32(K), 2);
  end;

  PUInt32Array(Dest)[0] := B;
  PUInt32Array(Dest)[1] := A;
end;

{ TCipher_Misty }

class function TCipher_Misty.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 128;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

function Misty_I(Value, Key: UInt32): UInt32;
begin
  Result := Misty_Data9[Value shr 7 and $1FF] xor (Value and $7F);
  Value := (Misty_Data7[Value and $7F] xor Result and $7F) xor (Key shr 9 and $7F);
  Result := Misty_Data9[Result xor (Key and $1FF)] xor Value or Value shl 9;
end;

function Misty_O(Value, K: UInt32; Key: PUInt32Array): UInt32;
begin
  Result := Misty_I((Value shr 16) xor Key[K], Key[(K + 5) and 7 + 8]) xor (Value and $FFFF);
  Value  := Misty_I((Value and $FFFF) xor Key[(K + 2) and 7], Key[(K + 1) and 7 + 8]) xor Result;
  Result := Misty_I(Result xor Key[(K + 7) and 7], Key[(K + 3) and 7 + 8]) xor Value;
  Result := Result or (Value xor Key[(K + 4) and 7]) shl 16;
end;

function Misty_E(Value, K: UInt32; Key: PUInt32Array): UInt32;
begin
  Result := Value shr 16;
  Value  := Value and $FFFF;

  if K and 1 <> 0 then
  begin
    K      := K shr 1;
    Value  := Value  xor (Result and Key[(K + 2) and 7 + 8]);
    Result := Result xor (Value  or  Key[(K + 4) and 7]);
  end
  else
  begin
    K      := K shr 1;
    Value  := Value  xor (Result and Key[K]);
    Result := Result xor (Value  or  Key[(K + 6) and 7 + 8]);
  end;

  Result:= (Result shl 16) or Value;
end;

function Misty_D(Value, K: UInt32; Key: PUInt32Array): UInt32;
begin
  Result := Value shr 16;
  Value  := Value and $FFFF;

  if K and 1 <> 0 then
  begin
    K      := K shr 1;
    Result := Result xor (Value  or  Key[(K + 4) and 7]);
    Value  := Value  xor (Result and Key[(K + 2) and 7 + 8]);
  end
  else
  begin
    K      := K shr 1;
    Result := Result xor (Value  or  Key[(K + 6) and 7 + 8]);
    Value  := Value  xor (Result and Key[K]);
  end;

  Result:= (Result shl 16) or Value;
end;

procedure TCipher_Misty.DoInit(const Key; Size: Integer);
var
  K: array[0..15] of Byte;
  D: PUInt32Array;
  I: Integer;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  D := FAdditionalBuffer;

  for I := 0 to 7 do
    D[I] := K[I * 2] * 256 + K[I * 2 + 1];

  for I := 0 to 7 do
  begin
    D[I +  8] := Misty_I(D[I], D[(I + 1) and 7]);
    D[I + 16] := D[I + 8] and $1FF;
    D[I + 24] := D[I + 8] shr 9;
  end;

  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_Misty.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  A, B: UInt32;
begin
  Assert(Size = Context.BlockSize);

  A := PUInt32Array(Source)[0];
  B := PUInt32Array(Source)[1];
  A := Misty_E(A, 0, FAdditionalBuffer);
  B := Misty_E(B, 1, FAdditionalBuffer) xor Misty_O(A, 0, FAdditionalBuffer);
  A := A xor Misty_O(B, 1, FAdditionalBuffer);
  A := Misty_E(A, 2, FAdditionalBuffer);
  B := Misty_E(B, 3, FAdditionalBuffer) xor Misty_O(A, 2, FAdditionalBuffer);
  A := A xor Misty_O(B, 3, FAdditionalBuffer);
  A := Misty_E(A, 4, FAdditionalBuffer);
  B := Misty_E(B, 5, FAdditionalBuffer) xor Misty_O(A, 4, FAdditionalBuffer);
  A := A xor Misty_O(B, 5, FAdditionalBuffer);
  A := Misty_E(A, 6, FAdditionalBuffer);
  B := Misty_E(B, 7, FAdditionalBuffer) xor Misty_O(A, 6, FAdditionalBuffer);
  A := A xor Misty_O(B, 7, FAdditionalBuffer);

  PUInt32Array(Dest)[0] := Misty_E(B, 9, FAdditionalBuffer);
  PUInt32Array(Dest)[1] := Misty_E(A, 8, FAdditionalBuffer);
end;

procedure TCipher_Misty.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  A, B: UInt32;
begin
  Assert(Size = Context.BlockSize);

  B := Misty_D(PUInt32Array(Source)[0], 9, FAdditionalBuffer);
  A := Misty_D(PUInt32Array(Source)[1], 8, FAdditionalBuffer);
  A := A xor Misty_O(B, 7, FAdditionalBuffer);
  B := Misty_D(B xor Misty_O(A, 6, FAdditionalBuffer), 7, FAdditionalBuffer);
  A := Misty_D(A, 6, FAdditionalBuffer);
  A := A xor Misty_O(B, 5, FAdditionalBuffer);
  B := Misty_D(B xor Misty_O(A, 4, FAdditionalBuffer), 5, FAdditionalBuffer);
  A := Misty_D(A, 4, FAdditionalBuffer);
  A := A xor Misty_O(B, 3, FAdditionalBuffer);
  B := Misty_D(B xor Misty_O(A, 2, FAdditionalBuffer), 3, FAdditionalBuffer);
  A := Misty_D(A, 2, FAdditionalBuffer);
  A := A xor Misty_O(B, 1, FAdditionalBuffer);

  PUInt32Array(Dest)[0] := Misty_D(A, 0, FAdditionalBuffer);
  PUInt32Array(Dest)[1] := Misty_D(B xor Misty_O(A, 0, FAdditionalBuffer), 1, FAdditionalBuffer);
end;

{ TCipher_NewDES }

procedure NewDES_Func(Source, Dest, Key: PByteArray);
var
  I: Integer;
  A, B, C, D, E, F, G, H: Byte;
begin
  A := Source[0];
  B := Source[1];
  C := Source[2];
  D := Source[3];
  E := Source[4];
  F := Source[5];
  G := Source[6];
  H := Source[7];

  for I := 0 to 7 do
  begin
    E := E xor NewDES_Data[A xor Key[0]];
    F := F xor NewDES_Data[B xor Key[1]];
    G := G xor NewDES_Data[C xor Key[2]];
    H := H xor NewDES_Data[D xor Key[3]];
    B := B xor NewDES_Data[E xor Key[4]];
    C := C xor NewDES_Data[F xor E];
    D := D xor NewDES_Data[G xor Key[5]];
    A := A xor NewDES_Data[H xor Key[6]];
    Key := @Key[7];
  end;

  E := E xor NewDES_Data[A xor Key[0]];
  F := F xor NewDES_Data[B xor Key[1]];
  G := G xor NewDES_Data[C xor Key[2]];
  H := H xor NewDES_Data[D xor Key[3]];

  Dest[0] := A;
  Dest[1] := B;
  Dest[2] := C;
  Dest[3] := D;
  Dest[4] := E;
  Dest[5] := F;
  Dest[6] := G;
  Dest[7] := H;
end;

class function TCipher_NewDES.Context: TCipherContext;
begin
  Result.KeySize                     := 15;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 60 * 2;
  Result.NeedsAdditionalBufferBackup := true;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_NewDES.DoInit(const Key; Size: Integer);
var
  K: array[0..14] of Byte;
  E: PByteArray;
  I: Integer;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  E := FAdditionalBuffer;
  Move(K, E[ 0], 15);
  Move(K, E[15], 15);
  Move(K, E[30], 15);
  Move(K, E[45], 15);
  E := @E[60];
  I := 11;

  repeat
    E[0] := K[I]; I := (I + 1) mod 15;
    E[1] := K[I]; I := (I + 1) mod 15;
    E[2] := K[I]; I := (I + 1) mod 15;
    E[3] := K[I]; I := (I + 9) mod 15;
    if I = 12 then
      Break;
    E[4] := K[I]; Inc(I);
    E[5] := K[I]; Inc(I);
    E[6] := K[I]; I := (I + 9) mod 15;
    E := @E[7];
  until False;

  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_NewDES.DoEncode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  NewDES_Func(Source, Dest, FAdditionalBuffer);
end;

procedure TCipher_NewDES.DoDecode(Source, Dest: Pointer; Size: Integer);
begin
  Assert(Size = Context.BlockSize);
  NewDES_Func(Source, Dest, @PByteArray(FAdditionalBuffer)[60]);
end;

{ TCipher_Q128 }

class function TCipher_Q128.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 16;
  Result.BufferSize                  := 16;
  Result.AdditionalBufferSize        := 256;
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Q128.DoInit(const Key; Size: Integer);
var
  K: array[0..3] of UInt32;
  D: PUInt32Array;
  I: Integer;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  D := FAdditionalBuffer;

  for I := 19 downto 1 do
  begin
    K[1] := K[1] xor Q128_Data[K[0] and $03FF]; K[0] := K[0] shr 10 or K[0] shl 22;
    K[2] := K[2] xor Q128_Data[K[1] and $03FF]; K[1] := K[1] shr 10 or K[1] shl 22;
    K[3] := K[3] xor Q128_Data[K[2] and $03FF]; K[2] := K[2] shr 10 or K[2] shl 22;
    K[0] := K[0] xor Q128_Data[K[3] and $03FF]; K[3] := K[3] shr 10 or K[3] shl 22;
    if I <= 16 then
    begin
      D[0] := K[0];
      D[1] := K[1];
      D[2] := K[2];
      D[3] := K[3];
      D := @D[4];
    end;
  end;

  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_Q128.DoEncode(Source, Dest: Pointer; Size: Integer);
{$IFDEF X86ASM}
asm
       PUSH   ESI
       PUSH   EDI
       PUSH   EBX
       PUSH   EBP
       PUSH   ECX
       MOV    EDI,[EAX].TCipher_Q128.FAdditionalBuffer
       MOV    EAX,[EDX +  0]  // B0
       MOV    EBX,[EDX +  4]  // B1
       MOV    ECX,[EDX +  8]  // B2
       MOV    EDX,[EDX + 12]  // B3
       MOV    EBP,16
@@1:   MOV    ESI,EAX
       ROL    ESI,10
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI + 0]
       XOR    EAX,EBX
       MOV    EBX,EAX
       ROL    EBX,10
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI + 4]
       XOR    EAX,ECX
       MOV    ECX,EAX
       ROL    ECX,10
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI + 8]
       XOR    EAX,EDX
       MOV    EDX,EAX
       ROL    EDX,10
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI + 12]
       XOR    EAX,ESI
       DEC    EBP
       LEA    EDI,[EDI + 16]
       JNZ    @@1
       POP    ESI
       MOV    [ESI +  0],EAX  // B0
       MOV    [ESI +  4],EBX  // B1
       MOV    [ESI +  8],ECX  // B2
       MOV    [ESI + 12],EDX  // B3
       POP    EBP
       POP    EBX
       POP    EDI
       POP    ESI
end;
{$ELSE !X86ASM}
var
  D: PUInt32Array;
  B0, B1, B2, B3, I: UInt32;
begin
  Assert(Size = Context.BlockSize);

  D  := Pointer(FBuffer);
  B0 := PUInt32Array(Source)[0];
  B1 := PUInt32Array(Source)[1];
  B2 := PUInt32Array(Source)[2];
  B3 := PUInt32Array(Source)[3];
  for I := 0 to 15 do
  begin
    B1 := B1 xor (Q128_Data[B0 and $03FF] + D[0]); B0 := B0 shl 10 or B0 shr 22;
    B2 := B2 xor (Q128_Data[B1 and $03FF] + D[1]); B1 := B1 shl 10 or B1 shr 22;
    B3 := B3 xor (Q128_Data[B2 and $03FF] + D[2]); B2 := B2 shl 10 or B2 shr 22;
    B0 := B0 xor (Q128_Data[B3 and $03FF] + D[3]); B3 := B3 shl 10 or B3 shr 22;
    D := @D[4];
  end;
  PUInt32Array(Dest)[0] := B0;
  PUInt32Array(Dest)[1] := B1;
  PUInt32Array(Dest)[2] := B2;
  PUInt32Array(Dest)[3] := B3;
end;
{$ENDIF !X86ASM}

procedure TCipher_Q128.DoDecode(Source, Dest: Pointer; Size: Integer);
{$IFDEF X86ASM}
asm
       PUSH   ESI
       PUSH   EDI
       PUSH   EBX
       PUSH   EBP
       PUSH   ECX
       MOV    EDI,[EAX].TCipher_Q128.FAdditionalBuffer
       LEA    EDI,[EDI + 64 * 4]
       MOV    ESI,[EDX +  0]   // B0
       MOV    EBX,[EDX +  4]  // B1
       MOV    ECX,[EDX +  8]  // B2
       MOV    EDX,[EDX + 12]  // B3
       MOV    EBP,16
@@1:   SUB    EDI,16
       ROR    EDX,10
       MOV    EAX,EDX
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI + 12]
       XOR    ESI,EAX
       ROR    ECX,10
       MOV    EAX,ECX
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI +  8]
       XOR    EDX,EAX
       ROR    EBX,10
       MOV    EAX,EBX
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI +  4]
       XOR    ECX,EAX
       ROR    ESI,10
       MOV    EAX,ESI
       AND    EAX,03FFh
       MOV    EAX,[EAX * 4 + OFFSET Q128_DATA]
       ADD    EAX,[EDI]
       XOR    EBX,EAX
       DEC    EBP
       JNZ    @@1
       POP    EAX
       MOV    [EAX +  0],ESI  // B0
       MOV    [EAX +  4],EBX  // B1
       MOV    [EAX +  8],ECX  // B2
       MOV    [EAX + 12],EDX  // B3
       POP    EBP
       POP    EBX
       POP    EDI
       POP    ESI
end;
{$ELSE !X86ASM}
var
  D: PUInt32Array;
  B0, B1, B2, B3, I: UInt32;
begin
  Assert(Size = Context.BlockSize);

  D  := @PUInt32Array(FBuffer)[60];
  B0 := PUInt32Array(Source)[0];
  B1 := PUInt32Array(Source)[1];
  B2 := PUInt32Array(Source)[2];
  B3 := PUInt32Array(Source)[3];
  for I := 0 to 15 do
  begin
    B3 := B3 shr 10 or B3 shl 22; B0 := B0 xor (Q128_Data[B3 and $03FF] + D[3]);
    B2 := B2 shr 10 or B2 shl 22; B3 := B3 xor (Q128_Data[B2 and $03FF] + D[2]);
    B1 := B1 shr 10 or B1 shl 22; B2 := B2 xor (Q128_Data[B1 and $03FF] + D[1]);
    B0 := B0 shr 10 or B0 shl 22; B1 := B1 xor (Q128_Data[B0 and $03FF] + D[0]);
    Dec(PUInt32(D), 4);
  end;
  PUInt32Array(Dest)[0] := B0;
  PUInt32Array(Dest)[1] := B1;
  PUInt32Array(Dest)[2] := B2;
  PUInt32Array(Dest)[3] := B3;
end;
{$ENDIF !X86ASM}

{ TCipher_RC2 }

class function TCipher_RC2.Context: TCipherContext;
begin
  Result.KeySize                     := 128;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 128;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_RC2.DoInit(const Key; Size: Integer);
// New keyscheduling according to RFC2268 and it's testcases. The V3 keysetup
// was using an older, inferior version. Special thanks to Brendan Bosnan for
// pointing that out.
var
  I, L, Mask, KeyEffectiveBits: Integer;
  K: PByteArray;
begin
  if Size <= 0 then
    Exit;
  KeyEffectiveBits := Size * 8;
  L := KeyEffectiveBits and 7;
  if L = 0 then
    Mask := $FF
  else
    Mask := $FF shr (8 - L);
  L := (KeyEffectiveBits + 7) shr 3;
  K := FAdditionalBuffer;
  Move(Key, K[0], Size);
  for I := Size to 127 do
    K[I] := RC2_Data[(K[I - Size] + K[I - 1]) and $FF];
  K[128 - L] := RC2_Data[K[128 - L] and Mask];
  for I := 127 - L downto 0 do
     K[I] := RC2_Data[K[I + 1] xor K[I + L]];
end;

procedure TCipher_RC2.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  K: PWordArray;
  A, B, C, D: Word;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  A := PWordArray(Source)[0];
  B := PWordArray(Source)[1];
  C := PWordArray(Source)[2];
  D := PWordArray(Source)[3];
  for I := 0 to 15 do
  begin
    Inc(A, (B and not D) + (C and D) + K[I * 4 + 0]); A := A shl 1 or A shr 15;
    Inc(B, (C and not A) + (D and A) + K[I * 4 + 1]); B := B shl 2 or B shr 14;
    Inc(C, (D and not B) + (A and B) + K[I * 4 + 2]); C := C shl 3 or C shr 13;
    Inc(D, (A and not C) + (B and C) + K[I * 4 + 3]); D := D shl 5 or D shr 11;
    if I in [4, 10] then
    begin
      Inc(A, K[D and $3F]);
      Inc(B, K[A and $3F]);
      Inc(C, K[B and $3F]);
      Inc(D, K[C and $3F]);
    end;
  end;
  PWordArray(Dest)[0] := A;
  PWordArray(Dest)[1] := B;
  PWordArray(Dest)[2] := C;
  PWordArray(Dest)[3] := D;
end;

procedure TCipher_RC2.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  K: PWordArray;
  A, B, C, D: Word;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  A := PWordArray(Source)[0];
  B := PWordArray(Source)[1];
  C := PWordArray(Source)[2];
  D := PWordArray(Source)[3];
  for I := 15 downto 0 do
  begin
    D := D shr 5 or D shl 11 - (A and not C) - (B and C) - K[I * 4 + 3];
    C := C shr 3 or C shl 13 - (D and not B) - (A and B) - K[I * 4 + 2];
    B := B shr 2 or B shl 14 - (C and not A) - (D and A) - K[I * 4 + 1];
    A := A shr 1 or A shl 15 - (B and not D) - (C and D) - K[I * 4 + 0];
    if I in [5, 11] then
    begin
      Dec(D, K[C and $3F]);
      Dec(C, K[B and $3F]);
      Dec(B, K[A and $3F]);
      Dec(A, K[D and $3F]);
    end;
  end;
  PWordArray(Dest)[0] := A;
  PWordArray(Dest)[1] := B;
  PWordArray(Dest)[2] := C;
  PWordArray(Dest)[3] := D;
end;

{ TCipher_RC5 }

class function TCipher_RC5.Context: TCipherContext;
begin
  Result.KeySize                     := 256;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 136;
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 256;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_RC5.SetRounds(Value: Integer);
begin
  if Value <> FRounds then
  begin
    if not (FState in [csNew, csInitialized, csDone]) then
      Done;
    if Value <= 0 then
      Value := 12;
    FRounds := Value;
  end;
end;

procedure TCipher_RC5.DoInit(const Key; Size: Integer);
var
  K: array[0..63] of UInt32;
  L, Z, I, J: Integer;
  D: PUInt32Array;
  A, B, T: UInt32;
begin
  if FRounds <= 0 then
    FRounds := 12;
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  D := FAdditionalBuffer;
  L := (Size + 3) shr 2;
  if L <= 0 then
    L := 1;
  T := $B7E15163;
  for I := 0 to (FRounds + 1) * 2 do
  begin
    D[I] := T;
    Inc(T, $9E3779B9);
  end;
  if L > (FRounds + 1) * 2 then
    Z := L * 3
  else
    Z := (FRounds + 1) * 6;
  I := 0;
  J := 0;
  A := 0;
  B := 0;
  for Z := Z downto 1 do
  begin
    A := D[I] + A + B;
    A := A shl 3 or A shr 29;
    D[I] := A;
    T := A + B;
    B := K[J] + T;
    B := B shl T or B shr (32 - T);
    K[J] := B;
    I := (I + 1) mod ((FRounds + 1) * 2);
    J := (J + 1) mod L;
  end;
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_RC5.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  K: PUInt32Array;
  I: Integer;
  A, B: UInt32;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  A := PUInt32Array(Source)[0] + K[0];
  B := PUInt32Array(Source)[1] + K[1];
  for I := 1 to FRounds do
  begin
    A := A xor B; A := A shl B or A shr (32 - B) + K[I * 2 + 0];
    B := B xor A; B := B shl A or B shr (32 - A) + K[I * 2 + 1];
  end;
  PUInt32Array(Dest)[0] := A;
  PUInt32Array(Dest)[1] := B;
end;

procedure TCipher_RC5.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  K: PUInt32Array;
  I: Integer;
  A, B: UInt32;
begin
  Assert(Size = Context.BlockSize);

  K := @PUInt32Array(FAdditionalBuffer)[0];
  A := PUInt32Array(Source)[0];
  B := PUInt32Array(Source)[1];
  for I := FRounds downto 1 do
  begin
    B := B - K[I * 2 + 1]; B := B shr A or B shl (32 - A) xor A;
    A := A - K[I * 2 + 0]; A := A shr B or A shl (32 - B) xor B;
  end;
  PUInt32Array(Dest)[0] := A - K[0];
  PUInt32Array(Dest)[1] := B - K[1];
end;

{ TCipher_SAFER }

class function TCipher_SAFER.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 768;
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 4;
  Result.MaxRounds                   := 13;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_SAFER.SetRounds(Value: Integer);
begin
  if not (FState in [csNew, csInitialized, csDone]) then
    Done;
  if (Value < 4) or (Value > 13) then
    case FVersion of // Default Rounds
      svK40, svSK40: Value := 5;
      svK64, svSK64: Value := 6;
      svK128, svSK128: Value := 10;
    else
      Value := 8;
    end;
  FRounds := Value;
end;

procedure TCipher_SAFER.SetVersion(Value: TSAFERVersion);
begin
  if Value <> FVersion then
  begin
    if not (FState in [csNew, csInitialized, csDone]) then
      Done;
    FVersion := Value;
    SetRounds(0);
  end;
end;

procedure TCipher_SAFER.DoInit(const Key; Size: Integer);

  procedure InitTab;
  var
    I, E: Integer;
    Exp: PByteArray;
    Log: PByteArray;
  begin
    Exp := FAdditionalBuffer;
    Log := @Exp[256];
    E   := 1;
    for I := 0 to 255 do
    begin
      Exp[I] := E and $FF;
      Log[E and $FF] := I;
      E := (E * 45) mod 257;
    end;
  end;

  procedure InitKey;
  var
    D: PByte;
    Exp: PByteArray;
    Strong: Boolean;
    K: array[Boolean, 0..8] of Byte;
    I, J: Integer;
  begin
    Strong := FVersion in [svSK40, svSK64, svSK128];
    Exp := FAdditionalBuffer;
    D := @Exp[512];
    FillChar(K, SizeOf(K), 0);
    // Setup Key A
    I := Size;
    if I > 8 then
      I := 8;
    Move(Key, K[False], I);
    // Setup the Key for K-40, SK-40
    if FVersion in [svK40, svSK40] then
    begin
      K[False, 5] := K[False, 0] xor K[False, 2] xor 129;
      K[False, 6] := K[False, 0] xor K[False, 3] xor K[False, 4] xor 66;
      K[False, 7] := K[False, 1] xor K[False, 2] xor K[False, 4] xor 36;
      K[False, 8] := K[False, 1] xor K[False, 3] xor 24;
      Move(K[False], K[True], SizeOf(K[False]));
    end
    else
    begin
      if Size > 8 then
      begin
        I := Size - 8;
        if I > 8 then
          I := 8;
        Move(TByteArray(Key)[8], K[True], I);
      end
      else
        Move(K[False], K[True], 9);
      for I := 0 to 7 do
      begin
        K[False, 8] := K[False, 8] xor K[False, I];
        K[True, 8]  := K[True, 8]  xor K[True, I];
      end;
    end;
    // Setup the KeyData
    Move(K[True], D^, 8);
    Inc(D, 8);

    for I := 0 to 8 do
      K[False, I] := K[False, I] shr 3 or K[False, I] shl 5;

    for I := 1 to FRounds do
    begin
      for J := 0 to 8 do
      begin
        K[False, J] := K[False, J] shl 6 or K[False, J] shr 2;
        K[True, J] := K[True, J] shl 6 or K[True, J] shr 2;
      end;
      for J := 0 to 7 do
      begin
        if Strong then
          D^ := K[False, (J + I * 2 - 1) mod 9] + Exp[Exp[18 * I + J + 1]]
        else
          D^ := K[False, J] + Exp[Exp[18 * I + J + 1]];
        Inc(D);
      end;
      for J := 0 to 7 do
      begin
        if Strong then
          D^ := K[True, (J + I * 2) mod 9] + Exp[Exp[18 * I + J + 10]]
        else
          D^ := K[True, J] + Exp[Exp[18 * I + J + 10]];
        Inc(D);
      end;
    end;
    ProtectBuffer(K, SizeOf(K));
  end;

begin
  if (FRounds < 4) or (FRounds > 13) then
    case FVersion of
      svK40, svSK40:    FRounds := 5;
      svK64, svSK64:    FRounds := 6;
      svK128, svSK128:  FRounds := 10;
    else
      FRounds := 8;
    end;
  InitTab;
  InitKey;
end;

procedure TCipher_SAFER.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  Exp, Log, Key: PByteArray;
  I: Integer;
  A, B, C, D, E, F, G, H, T: Byte;
begin
  Assert(Size = Context.BlockSize);

  Exp := FAdditionalBuffer;
  Log := @Exp[256];
  Key := @Exp[512];

  A := PByteArray(Source)[0];
  B := PByteArray(Source)[1];
  C := PByteArray(Source)[2];
  D := PByteArray(Source)[3];
  E := PByteArray(Source)[4];
  F := PByteArray(Source)[5];
  G := PByteArray(Source)[6];
  H := PByteArray(Source)[7];

  for I := 0 to FRounds - 1 do
  begin
    A := A xor Key[0];
    B := B  +  Key[1];
    C := C  +  Key[2];
    D := D xor Key[3];
    E := E xor Key[4];
    F := F  +  Key[5];
    G := G  +  Key[6];
    H := H xor Key[7];

    A := Exp[A]  +  Key[8];
    B := Log[B] xor Key[9];
    C := Log[C] xor Key[10];
    D := Exp[D]  +  Key[11];
    E := Exp[E]  +  Key[12];
    F := Log[F] xor Key[13];
    G := Log[G] xor Key[14];
    H := Exp[H]  +  Key[15];
    Inc(B, A); Inc(A, B);
    Inc(D, C); Inc(C, D);
    Inc(F, E); Inc(E, F);
    Inc(H, G); Inc(G, H);
    Inc(C, A); Inc(A, C);
    Inc(G, E); Inc(E, G);
    Inc(D, B); Inc(B, D);
    Inc(H, F); Inc(F, H);
    Inc(E, A); Inc(A, E);
    Inc(F, B); Inc(B, F);
    Inc(G, C); Inc(C, G);
    Inc(H, D); Inc(D, H);
    T := B; B := E; E := C; C := T;
    T := D; D := F; F := G; G := T;
    Key := @Key[16];
  end;

  PByteArray(Dest)[0] := A xor Key[0];
  PByteArray(Dest)[1] := B  +  Key[1];
  PByteArray(Dest)[2] := C  +  Key[2];
  PByteArray(Dest)[3] := D xor Key[3];
  PByteArray(Dest)[4] := E xor Key[4];
  PByteArray(Dest)[5] := F  +  Key[5];
  PByteArray(Dest)[6] := G  +  Key[6];
  PByteArray(Dest)[7] := H xor Key[7];
end;

procedure TCipher_SAFER.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  Exp, Log, Key: PByteArray;
  I: Integer;
  A, B, C, D, E, F, G, H, T: Byte;
begin
  Assert(Size = Context.BlockSize);

  Exp := FAdditionalBuffer;
  Log := @Exp[256];
  Key := @Exp[504 + 8 * (FRounds * 2 + 1)];

  A := PByteArray(Source)[0] xor Key[0];
  B := PByteArray(Source)[1]  -  Key[1];
  C := PByteArray(Source)[2]  -  Key[2];
  D := PByteArray(Source)[3] xor Key[3];
  E := PByteArray(Source)[4] xor Key[4];
  F := PByteArray(Source)[5]  -  Key[5];
  G := PByteArray(Source)[6]  -  Key[6];
  H := PByteArray(Source)[7] xor Key[7];

  for I := 0 to FRounds - 1 do
  begin
    Dec(PByte(Key), 16);
    T := E; E := B; B := C; C := T;
    T := F; F := D; D := G; G := T;
    Dec(A, E); Dec(E, A);
    Dec(B, F); Dec(F, B);
    Dec(C, G); Dec(G, C);
    Dec(D, H); Dec(H, D);
    Dec(A, C); Dec(C, A);
    Dec(E, G); Dec(G, E);
    Dec(B, D); Dec(D, B);
    Dec(F, H); Dec(H, F);
    Dec(A, B); Dec(B, A);
    Dec(C, D); Dec(D, C);
    Dec(E, F); Dec(F, E);
    Dec(G, H); Dec(H, G);
    H := H  -  Key[15];
    G := G xor Key[14];
    F := F xor Key[13];
    E := E  -  Key[12];
    D := D  -  Key[11];
    C := C xor Key[10];
    B := B xor Key[9];
    A := A  -  Key[8];
    H := Log[H] xor Key[7];
    G := Exp[G]  -  Key[6];
    F := Exp[F]  -  Key[5];
    E := Log[E] xor Key[4];
    D := Log[D] xor Key[3];
    C := Exp[C]  -  Key[2];
    B := Exp[B]  -  Key[1];
    A := Log[A] xor Key[0];
  end;

  PByteArray(Dest)[0] := A;
  PByteArray(Dest)[1] := B;
  PByteArray(Dest)[2] := C;
  PByteArray(Dest)[3] := D;
  PByteArray(Dest)[4] := E;
  PByteArray(Dest)[5] := F;
  PByteArray(Dest)[6] := G;
  PByteArray(Dest)[7] := H;
end;

{ TCipher_Shark }

type
  PLong64 = ^TLong64;
  TLong64  = packed record
    L, R: UInt32;
  end;

  PLong64Array = ^TLong64Array;
  TLong64Array = array[0..1023] of TLong64;

class function TCipher_Shark.Context: TCipherContext;
begin
  Result.KeySize                     := 16;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := 112;
  Result.NeedsAdditionalBufferBackup := False;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Shark.DoInit(const Key; Size: Integer);
var
  Log, ALog: array[0..255] of Byte;

  procedure InitLog;
  var
    I, J: Word;
  begin
    ALog[0] := 1;
    for I := 1 to 255 do
    begin
      J := ALog[I - 1] shl 1;
      if J and $100 <> 0 then
        J := J xor $01F5;
      ALog[I] := J;
    end;
    for I := 1 to 254 do
      Log[ALog[I]] := I;
  end;

  function Transform(A: TLong64): TLong64;

    function Mul(A, B: Integer): Byte;
    begin
      Result := ALog[(Log[A] + Log[B]) mod 255];
    end;

  var
    I, J: Byte;
    K, T: array[0..7] of Byte;
  begin
    Move(A.R, K[0], 4);
    Move(A.L, K[4], 4);
    SwapUInt32Buffer(K, K, 2);
    for I := 0 to 7 do
    begin
      T[I] := Mul(Shark_I[I, 0], K[0]);
      for J := 1 to 7 do
        T[I] := T[I] xor Mul(Shark_I[I, J], K[J]);
    end;
    Result.L := T[0];
    Result.R := 0;
    for I := 1 to 7 do
    begin
      Result.R := Result.R shl 8 or Result.L shr 24;
      Result.L := Result.L shl 8 xor T[I];
    end;
  end;

  function Shark(D: TLong64; K: PLong64): TLong64;
  var
    R, T: Integer;
  begin
    for R := 0 to 4 do
    begin
      D.L := D.L xor K.L;
      D.R := D.R xor K.R;
      Inc(K);
      T   := Shark_CE[0, D.R shr 23 and $1FE] xor
             Shark_CE[1, D.R shr 15 and $1FE] xor
             Shark_CE[2, D.R shr  7 and $1FE] xor
             Shark_CE[3, D.R shl  1 and $1FE] xor
             Shark_CE[4, D.L shr 23 and $1FE] xor
             Shark_CE[5, D.L shr 15 and $1FE] xor
             Shark_CE[6, D.L shr  7 and $1FE] xor
             Shark_CE[7, D.L shl  1 and $1FE];

      D.R := Shark_CE[0, D.R shr 23 and $1FE or 1] xor
             Shark_CE[1, D.R shr 15 and $1FE or 1] xor
             Shark_CE[2, D.R shr  7 and $1FE or 1] xor
             Shark_CE[3, D.R shl  1 and $1FE or 1] xor
             Shark_CE[4, D.L shr 23 and $1FE or 1] xor
             Shark_CE[5, D.L shr 15 and $1FE or 1] xor
             Shark_CE[6, D.L shr  7 and $1FE or 1] xor
             Shark_CE[7, D.L shl  1 and $1FE or 1];
      D.L := T;
    end;
    D.L := D.L xor K.L;
    D.R := D.R xor K.R;
    Inc(K);
    D.L := UInt32(Shark_SE[D.L shr 24 and $FF]) shl 24 xor
           UInt32(Shark_SE[D.L shr 16 and $FF]) shl 16 xor
           UInt32(Shark_SE[D.L shr  8 and $FF]) shl  8 xor
           UInt32(Shark_SE[D.L        and $FF]);
    D.R := UInt32(Shark_SE[D.R shr 24 and $FF]) shl 24 xor
           UInt32(Shark_SE[D.R shr 16 and $FF]) shl 16 xor
           UInt32(Shark_SE[D.R shr  8 and $FF]) shl  8 xor
           UInt32(Shark_SE[D.R        and $FF]);
    Result.L := D.L xor K.L;
    Result.R := D.R xor K.R;
  end;

var
  T: array[0..6] of TLong64;
  A: array[0..6] of TLong64;
  K: array[0..15] of Byte;
  I, J, R: Byte;
  E, D: PLong64Array;
  L: TLong64;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  InitLog;
  E := FAdditionalBuffer;
  D := @E[7];
  Move(Shark_CE[0], T, SizeOf(T));
  T[6] := Transform(T[6]);
  I := 0;
  for R := 0 to 6 do
  begin
    Inc(I);
    A[R].L := K[I and $F];
    A[R].R := 0;
    for J := 1 to 7 do
    begin
      Inc(I);
      A[R].R := A[R].R shl 8 or A[R].L shr 24;
      A[R].L := A[R].L shl 8 or K[I and $F];
    end;
  end;
  L.L := 0;
  L.R := 0;
  L := Shark(L, @T);
  E[0].L := A[0].L xor L.L;
  E[0].R := A[0].R xor L.R;
  for R := 1 to 6 do
  begin
    L := Shark(E[R - 1], @T);
    E[R].L := A[R].L xor L.L;
    E[R].R := A[R].R xor L.R;
  end;
  E[6] := Transform(E[6]);
  D[0] := E[6];
  D[6] := E[0];
  for R := 1 to 5 do
    D[R] := Transform(E[6-R]);
  ProtectBuffer(Log, SizeOf(Log));
  ProtectBuffer(ALog, SizeOf(ALog));
  ProtectBuffer(T, SizeOf(T));
  ProtectBuffer(A, SizeOf(A));
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_Shark.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  T, L, R: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := FAdditionalBuffer;
  L := PLong64(Source).L;
  R := PLong64(Source).R;
  for I := 0 to 4 do
  begin
    L := L xor K[I * 2 + 0];
    R := R xor K[I * 2 + 1];
    T := Shark_CE[0, R shr 23 and $1FE] xor
         Shark_CE[1, R shr 15 and $1FE] xor
         Shark_CE[2, R shr  7 and $1FE] xor
         Shark_CE[3, R shl  1 and $1FE] xor
         Shark_CE[4, L shr 23 and $1FE] xor
         Shark_CE[5, L shr 15 and $1FE] xor
         Shark_CE[6, L shr  7 and $1FE] xor
         Shark_CE[7, L shl  1 and $1FE];
    R := Shark_CE[0, R shr 23 and $1FE or 1] xor
         Shark_CE[1, R shr 15 and $1FE or 1] xor
         Shark_CE[2, R shr  7 and $1FE or 1] xor
         Shark_CE[3, R shl  1 and $1FE or 1] xor
         Shark_CE[4, L shr 23 and $1FE or 1] xor
         Shark_CE[5, L shr 15 and $1FE or 1] xor
         Shark_CE[6, L shr  7 and $1FE or 1] xor
         Shark_CE[7, L shl  1 and $1FE or 1];
    L := T;
  end;
  L := L xor K[10];
  R := R xor K[11];
  L := UInt32(Shark_SE[L shr 24        ]) shl 24 xor
       UInt32(Shark_SE[L shr 16 and $FF]) shl 16 xor
       UInt32(Shark_SE[L shr  8 and $FF]) shl  8 xor
       UInt32(Shark_SE[L        and $FF]);
  R := UInt32(Shark_SE[R shr 24        ]) shl 24 xor
       UInt32(Shark_SE[R shr 16 and $FF]) shl 16 xor
       UInt32(Shark_SE[R shr  8 and $FF]) shl  8 xor
       UInt32(Shark_SE[R        and $FF]);
  PLong64(Dest).L := L xor K[12];
  PLong64(Dest).R := R xor K[13];
end;

procedure TCipher_Shark.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  T, R, L: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  K := @PUInt32Array(FAdditionalBuffer)[14];
  L := PLong64(Source).L;
  R := PLong64(Source).R;
  for I := 0 to 4 do
  begin
    L := L xor K[I * 2 + 0];
    R := R xor K[I * 2 + 1];
    T := Shark_CD[0, R shr 23 and $1FE] xor
         Shark_CD[1, R shr 15 and $1FE] xor
         Shark_CD[2, R shr  7 and $1FE] xor
         Shark_CD[3, R shl  1 and $1FE] xor
         Shark_CD[4, L shr 23 and $1FE] xor
         Shark_CD[5, L shr 15 and $1FE] xor
         Shark_CD[6, L shr  7 and $1FE] xor
         Shark_CD[7, L shl  1 and $1FE];
    R := Shark_CD[0, R shr 23 and $1FE or 1] xor
         Shark_CD[1, R shr 15 and $1FE or 1] xor
         Shark_CD[2, R shr  7 and $1FE or 1] xor
         Shark_CD[3, R shl  1 and $1FE or 1] xor
         Shark_CD[4, L shr 23 and $1FE or 1] xor
         Shark_CD[5, L shr 15 and $1FE or 1] xor
         Shark_CD[6, L shr  7 and $1FE or 1] xor
         Shark_CD[7, L shl  1 and $1FE or 1];
    L := T;
  end;
  L := L xor K[10];
  R := R xor K[11];
  L := UInt32(Shark_SD[L shr 24        ]) shl 24 xor
       UInt32(Shark_SD[L shr 16 and $FF]) shl 16 xor
       UInt32(Shark_SD[L shr  8 and $FF]) shl  8 xor
       UInt32(Shark_SD[L        and $FF]);
  R := UInt32(Shark_SD[R shr 24        ]) shl 24 xor
       UInt32(Shark_SD[R shr 16 and $FF]) shl 16 xor
       UInt32(Shark_SD[R shr  8 and $FF]) shl  8 xor
       UInt32(Shark_SD[R        and $FF]);
  PLong64(Dest).L := L xor K[12];
  PLong64(Dest).R := R xor K[13];
end;

{ TCipher_Skipjack }

class function TCipher_Skipjack.Context: TCipherContext;
begin
  Result.KeySize                     := 10;
  Result.BlockSize                   := 8;
  Result.BufferSize                  := 8;
  Result.AdditionalBufferSize        := $A00;
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 1;
  Result.MaxRounds                   := 1;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_Skipjack.DoInit(const Key; Size: Integer);
var
  K: array[0..9] of Byte;
  D: PByte;
  I, J: Integer;
begin
  FillChar(K, SizeOf(K), 0);
  Move(Key, K, Size);
  D := FAdditionalBuffer;
  for I := 0 to 9 do
    for J := 0 to 255 do
    begin
      D^ := Skipjack_Data[J xor K[I]];
      Inc(D);
    end;
  ProtectBuffer(K, SizeOf(K));
end;

procedure TCipher_Skipjack.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  Tab, Min: PSkipjackTab;
  Max: PByte;
  K, T, A, B, C, D: UInt32;

begin
  Assert(Size = Context.BlockSize);

  Min := FAdditionalBuffer;
  Max := PByte(Min) + 9 * 256; // for Pointer Math
  Tab := Min;
  A   := Swap(PWordArray(Source)[0]);
  B   := Swap(PWordArray(Source)[1]);
  C   := Swap(PWordArray(Source)[2]);
  D   := Swap(PWordArray(Source)[3]);
  K   := 0;

  repeat
    Inc(K);
    T := A;
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    A := T xor D xor K;
    D := C;
    C := B;
    B := T;
  until K = 8;

  repeat
    Inc(K);
    T := A;
    A := D;
    D := C;
    C := T xor B xor K;
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    B := T;
  until K = 16;

  repeat
    Inc(K);
    T := A;
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    A := T xor D xor K;
    D := C;
    C := B;
    B := T;
  until K = 24;

  repeat
    Inc(K);
    T := A;
    A := D;
    D := C;
    C := T xor B xor K;
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackIncCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackIncCheck(Tab, Min, Max);
    B := T;
  until K = 32;

  PWordArray(Dest)[0] := Swap(A);
  PWordArray(Dest)[1] := Swap(B);
  PWordArray(Dest)[2] := Swap(C);
  PWordArray(Dest)[3] := Swap(D);
end;

procedure TCipher_Skipjack.SkipjackIncCheck(var ATab: PSkipjackTab; AMin: PSkipjackTab; AMax: PByte);
begin
  Inc(ATab);

  if PByte(ATab) > AMax then
    ATab := AMin;
end;

procedure TCipher_Skipjack.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  Tab, Max: PSkipjackTab;
  Min: PByte; // for Pointer Math
  K, T, A, B, C, D: UInt32;

begin
  Assert(Size = Context.BlockSize);

  Min := FAdditionalBuffer;
  Max := Pointer(Min + 9 * 256);
  Tab := Pointer(Min + 7 * 256);
  A   := Swap(PWordArray(Source)[0]); // holds an Integer, Compiler makes faster Code
  B   := Swap(PWordArray(Source)[1]);
  C   := Swap(PWordArray(Source)[2]);
  D   := Swap(PWordArray(Source)[3]);
  K   := 32;

  repeat
    T := B;
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    B := T xor C xor K;
    C := D;
    D := A;
    A := T;
    Dec(K);
  until K = 24;

  repeat
    T := B;
    B := C;
    C := D;
    D := T xor A xor K;
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    A := T;
    Dec(K);
  until K = 16;

  repeat
    T := B;
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    B := C xor T xor K;
    C := D;
    D := A;
    A := T;
    Dec(K);
  until K = 8;

  repeat
    T := B;
    B := C;
    C := D;
    D := T xor A xor K;
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T shr 8];           SkipjackDecCheck(Tab, Min, Max);
    T := T xor Tab[T and $FF] shl 8;   SkipjackDecCheck(Tab, Min, Max);
    A := T;
    Dec(K);
  until K = 0;

  PWordArray(Dest)[0] := Swap(A);
  PWordArray(Dest)[1] := Swap(B);
  PWordArray(Dest)[2] := Swap(C);
  PWordArray(Dest)[3] := Swap(D);
end;

procedure TCipher_Skipjack.SkipjackDecCheck(var ATab: PSkipjackTab; AMin: PByte; AMax: PSkipjackTab);
begin
  Dec(ATab);
//    {$IFDEF DELPHIORBCB}
//    if ATab < AMin then
//    {$ELSE !DELPHIORBCB}
{ TODO : Pr�fen ob so korrekt, da ATab auf PByte umgestellt wurde, au�erdem sollte
diese interne procedure eher zu einer strict private methode werden}
  if PByte(ATab) < AMin then
//    {$ENDIF !DELPHIORBCB}
    ATab := AMax;
end;

{ TCipher_TEA }

const
  TEA_Delta = $9E3779B9; // magic constant, decimal 2654435769

class function TCipher_TEA.Context: TCipherContext;
begin
  Result.KeySize                     := 16;   // 128 bits
  Result.BlockSize                   := 8;    // 64 bits
  Result.BufferSize                  := 8;    // 64 bits
  Result.AdditionalBufferSize        := 32;   // 256 bits
  Result.NeedsAdditionalBufferBackup := false;
  Result.MinRounds                   := 16;
  Result.MaxRounds                   := 256;
  Result.CipherType                  := [ctSymmetric, ctBlock];
end;

procedure TCipher_TEA.SetRounds(Value: Integer);
begin
  if not (FState in [csNew, csInitialized, csDone]) then
    Done;
  if Value < 16 then
    Value := 16
  else
  if Value > 256 then
    Value := 256;
  FRounds := Value;
end;

procedure TCipher_TEA.DoInit(const Key; Size: Integer);
begin
  Move(Key, FAdditionalBuffer^, Size);
  SetRounds(FRounds);
end;

procedure TCipher_TEA.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  Sum,
  X, Y, A, B, C, D: UInt32;
begin
  Assert(Size = Context.BlockSize);

  Sum := 0;

  A := PUInt32Array(FAdditionalBuffer)[0];
  B := PUInt32Array(FAdditionalBuffer)[1];
  C := PUInt32Array(FAdditionalBuffer)[2];
  D := PUInt32Array(FAdditionalBuffer)[3];
  X := PUInt32Array(Source)[0];
  Y := PUInt32Array(Source)[1];

  for I := 0 to FRounds - 1 do
  begin
    Inc(Sum, TEA_Delta);
    Inc(X, (((Y shl 4 + A) xor Y) + Sum) xor (Y shr 5 + B));
    Inc(Y, (((X shl 4 + C) xor X) + Sum) xor (X shr 5 + D));
  end;

  PUInt32Array(Dest)[0] := X;
  PUInt32Array(Dest)[1] := Y;
end;

procedure TCipher_TEA.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  Sum,
  X, Y, A, B, C, D: UInt32;
begin
  Assert(Size = Context.BlockSize);

  Sum := TEA_Delta * UInt32(FRounds);

  A := PUInt32Array(FAdditionalBuffer)[0];
  B := PUInt32Array(FAdditionalBuffer)[1];
  C := PUInt32Array(FAdditionalBuffer)[2];
  D := PUInt32Array(FAdditionalBuffer)[3];
  X := PUInt32Array(Source)[0];
  Y := PUInt32Array(Source)[1];

  for I := 0 to FRounds - 1 do
  begin
    Dec(Y, (X shl 4 + C) xor X + Sum xor (X shr 5 + D));
    Dec(X, (Y shl 4 + A) xor Y + Sum xor (Y shr 5 + B));
    Dec(Sum, TEA_Delta);
  end;

  PUInt32Array(Dest)[0] := X;
  PUInt32Array(Dest)[1] := Y;
end;

{ TCipher_XTEA }

procedure TCipher_XTEA.DoEncode(Source, Dest: Pointer; Size: Integer);
var
  Sum,
  I, X, Y: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  Sum := 0;

  X := PUInt32Array(Source)[0];
  Y := PUInt32Array(Source)[1];
  K := FAdditionalBuffer;

  for I := 0 to FRounds - 1 do
  begin
    Inc(X, (((Y shl 4) xor (Y shr 5)) + Y) xor (Sum + K[Sum and 3]));
    Inc(Sum, TEA_Delta);
    Inc(Y, (((X shl 4) xor (X shr 5)) + X) xor (Sum + K[Sum shr 11 and 3]));
  end;

  PUInt32Array(Dest)[0] := X;
  PUInt32Array(Dest)[1] := Y;
end;

procedure TCipher_XTEA.DoDecode(Source, Dest: Pointer; Size: Integer);
var
  I: Integer;
  Sum,
  X, Y: UInt32;
  K: PUInt32Array;
begin
  Assert(Size = Context.BlockSize);

  Sum := TEA_Delta * UInt32(FRounds);

  X := PUInt32Array(Source)[0];
  Y := PUInt32Array(Source)[1];
  K := FAdditionalBuffer;

  for I := 0 to FRounds - 1 do
  begin
    Dec(Y, (((X shl 4) xor (X shr 5)) + X) xor (Sum + K[Sum shr 11 and 3]));
    Dec(Sum, TEA_Delta);
    Dec(X, (((Y shl 4) xor (Y shr 5)) + Y) xor (Sum + K[Sum and 3]));
  end;

  PUInt32Array(Dest)[0] := X;
  PUInt32Array(Dest)[1] := Y;
end;

{$IFDEF RESTORE_RANGECHECKS}{$R+}{$ENDIF}
{$IFDEF RESTORE_OVERFLOWCHECKS}{$Q+}{$ENDIF}

initialization
  SetDefaultCipherClass(TCipher_Null);

  {$IFNDEF ManualRegisterClasses}
  TCipher_Null.RegisterClass(TDECCipher.ClassList);
  TCipher_Blowfish.RegisterClass(TDECCipher.ClassList);
  TCipher_Twofish.RegisterClass(TDECCipher.ClassList);
  TCipher_IDEA.RegisterClass(TDECCipher.ClassList);
  TCipher_Cast256.RegisterClass(TDECCipher.ClassList);
  TCipher_Mars.RegisterClass(TDECCipher.ClassList);
  TCipher_RC4.RegisterClass(TDECCipher.ClassList);
  TCipher_RC6.RegisterClass(TDECCipher.ClassList);
// Explicitely not registered, as Rijndael is 1:1 the same as AES and AES is the
// more common name
//  TCipher_Rijndael.RegisterClass(TDECCipher.ClassList);
  TCipher_AES.RegisterClass(TDECCipher.ClassList);
  TCipher_Square.RegisterClass(TDECCipher.ClassList);
  TCipher_SCOP.RegisterClass(TDECCipher.ClassList);
  TCipher_Sapphire.RegisterClass(TDECCipher.ClassList);
  TCipher_1DES.RegisterClass(TDECCipher.ClassList);
  TCipher_2DES.RegisterClass(TDECCipher.ClassList);
  TCipher_3DES.RegisterClass(TDECCipher.ClassList);
  TCipher_2DDES.RegisterClass(TDECCipher.ClassList);
  TCipher_3DDES.RegisterClass(TDECCipher.ClassList);
  TCipher_3TDES.RegisterClass(TDECCipher.ClassList);
  TCipher_3Way.RegisterClass(TDECCipher.ClassList);
  TCipher_Cast128.RegisterClass(TDECCipher.ClassList);
  TCipher_Gost.RegisterClass(TDECCipher.ClassList);
// Explicitely not registered, as this is an alias for Gost only
//  TCipher_Magma.RegisterClass(TDECCipher.ClassList);
  TCipher_Misty.RegisterClass(TDECCipher.ClassList);
  TCipher_NewDES.RegisterClass(TDECCipher.ClassList);
  TCipher_Q128.RegisterClass(TDECCipher.ClassList);
  TCipher_RC2.RegisterClass(TDECCipher.ClassList);
  TCipher_RC5.RegisterClass(TDECCipher.ClassList);
  TCipher_SAFER.RegisterClass(TDECCipher.ClassList);
  TCipher_Shark.RegisterClass(TDECCipher.ClassList);
  TCipher_Skipjack.RegisterClass(TDECCipher.ClassList);
  TCipher_TEA.RegisterClass(TDECCipher.ClassList);
  TCipher_XTEA.RegisterClass(TDECCipher.ClassList);
  TCipher_TEAN.RegisterClass(TDECCipher.ClassList);
  {$ENDIF}

finalization

end.
