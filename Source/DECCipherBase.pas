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
unit DECCipherBase;
{$INCLUDE DECOptions.inc}

interface


uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes, Generics.Collections,
  {$ENDIF}
  DECBaseClass, DECFormatBase, DECTypes;

type
  /// <summary>
  ///   Possible kindes of cipher algorithms independent of any block
  ///   concatenation mode etc.
  ///   <para>
  ///     ctNull = special "do nothing cipher"
  ///    </para>
  ///   <para>
  ///     ctStream = cipher operating on a stream of bytes instead of blocks
  ///    </para>
  ///   <para>
  ///     ctBlock = cipher operating on blocks of bytes with a fixed size
  ///    </para>
  ///   <para>
  ///     ctSymmetric = cipher where the same key encrypts and decrypts
  ///    </para>
  ///   <para>
  ///     ctAsymetric = cipher where encryption and decryption requires
  ///                   different keys
  ///    </para>
  /// </summary>
  TCipherTypes = (ctNull, ctStream, ctBlock, ctSymmetric, ctAsymmetric);

  /// <summary>
  ///   Actual kind of cipher algorithm
  /// </summary>
  TCipherType = set of TCipherTypes;

  /// <summary>
  ///   Padding used to fill the last incomplete block of a block encryption
  ///   algorithm.
  /// </summary>
  /// <remark>
  ///   Try to avoid pmPKCS5, as this is a subset of pmPKCS7 anyway and replaced
  ///   by that one
  /// </remark>
  TPaddingMode = (pmNone, pmPKCS5, pmPKCS7, pmANSI_X9_23 , pmISO10126, pmISO7816);

  /// <summary>
  ///   Record containing meta data about a certain cipher
  /// </summary>
  TCipherContext = packed record
    /// <summary>
    ///   maximal key size in bytes
    /// </summary>
    KeySize    : Integer;
    /// <summary>
    ///   mininmal block size in bytes, e.g. 1 = Streamcipher
    /// </summary>
    BlockSize  : Integer;
    /// <summary>
    ///   internal buffersize in bytes
    /// </summary>
    BufferSize : Integer;
    /// <summary>
    ///   Size in bytes of the FAdditionalBuffer used by some of the cipher algorithms
    /// </summary>
    AdditionalBufferSize   : Integer;
    /// <summary>
    ///   When true the memory a certain internal pointer (FAdditionalBuffer)
    ///   points to needs to be backuped during key initialization if no init
    ///   vector is specified and restored at the end of that init method.
    ///   Same in Done method as well.
    /// </summary>
    NeedsAdditionalBufferBackup : Boolean;
    /// <summary>
    ///   Minimum number of rounds allowed for any block cipher having a rounds
    ///   property. In all other cases it will be set to 1.
    /// </summary>
    MinRounds : UInt16;
    /// <summary>
    ///   Maximum number of rounds allowed for any block cipher having a rounds
    ///   property. In all other cases it will be set to 1.
    /// </summary>
    MaxRounds : UInt16;

    /// <summary>
    ///   Specifies the kind of cipher
    /// </summary>
    CipherType : TCipherType;
  end;

  /// <summary>
  ///   TCipher.State represents the internal state of processing
  /// <para>
  ///   csNew : cipher isn't initialized, .Init() must be called before en/decode
  /// </para>
  /// <para>
  ///   csInitialized : cipher is initialized by .Init(), i.e. Keysetup was processed
  /// </para>
  /// <para>
  ///   csEncode : Encoding was started, and more chunks can be encoded, but not decoded
  /// </para>
  /// <para>
  ///   csDecode : Decoding was started, and more chunks can be decoded, but not encoded
  /// </para>
  /// <para>
  ///   csPadded : trough En/Decoding the messagechunks are padded, no more chunks can
  ///                   be processed, the cipher is blocked
  /// </para>
  /// <para>
  ///   csDone : Processing is finished and Cipher.Done was called. Now, new En/Decoding
  ///            can be started without calling .Init() before. csDone is basically
  ///            identical to csInitialized, except Cipher.Buffer holds the encrypted
  ///            last state of Cipher.Feedback which can be used as
  ///            Cipher-based message authentication code (CMAC).
  /// </para>
  /// </summary>
  TCipherState = (csNew, csInitialized, csEncode, csDecode, csPadded, csDone);
  /// <summary>
  ///   Set of cipher states, representing the internal state of processing
  /// </summary>
  TCipherStates = set of TCipherState;

  /// <summary>
  ///   This defines how the individual blocks of the data to be processed are
  ///   linked with each other.
  ///
  ///   Modes cmCBCx, cmCTSx, cmCTSxx, cmCFBx, cmOFBx, cmCFSx, cmECBx are working
  ///   on Blocks of Cipher.BufferSize bytes, when using a Blockcipher that's equal
  ///   to Cipher.BlockSize.
  ///
  ///   Modes cmCFB8, cmOFB8, cmCFS8 work on 8 bit Feedback Shift Registers.
  ///
  ///   Modes cmCTSx, cmCFSx, cmCFS8 are proprietary modes developed by Hagen
  ///   Reddmann. These modes work like cmCBCx, cmCFBx, cmCFB8 but with double
  ///   XOR'ing of the inputstream into the feedback register.
  ///
  ///   Mode cmECBx needs message padding to be a multiple of Cipher.BlockSize and
  ///   should be used only in 1-byte Streamciphers.
  ///
  ///   Modes cmCFB8, cmCFBx, cmOFB8, cmOFBx, cmCFS8 and cmCFSx need no padding.
  ///
  ///   Modes cmCTSx, cmCBCx need no external padding, because internally the last
  ///   truncated block is padded by cmCFS8 or cmCFB8. After padding these Modes
  ///   cannot be used to process any more data. If needed to process chunks of
  ///   data then each chunk must be algined to Cipher.BufferSize bytes.
  ///
  ///   Mode cmCTS3 is a proprietary mode developed by Frederik Winkelsdorf. It
  ///   replaces the CFS8 padding of the truncated final block with a CFSx padding.
  ///   Useful when converting projects that previously used the old DEC v3.0. It
  ///   has the same restrictions for external padding and chunk processing as
  ///   cmCTSx has.
  /// </summary>
  TCipherMode = (
    cmCTSx,   // double CBC, with CFS8 padding of truncated final block
    cmCBCx,   // Cipher Block Chaining, with CFB8 padding of truncated final block
    cmCFB8,   // 8bit Cipher Feedback mode
    cmCFBx,   // CFB on Blocksize of Cipher
    cmOFB8,   // 8bit Output Feedback mode
    cmOFBx,   // OFB on Blocksize bytes
    cmCFS8,   // 8Bit CFS, double CFB
    cmCFSx,   // CFS on Blocksize bytes
    cmECBx,   // Electronic Code Book
    cmGCM     // Galois Counter Mode
    {$IFDEF DEC3_CMCTS}
    ,cmCTS3   // double CBC, with less secure padding of truncated final block
              // for DEC 3.0 compatibility only (see DECOptions.inc)
    {$ENDIF DEC3_CMCTS}
  );

  /// <summary>
  ///   Each cipher algorithm has to implement a Encode and a Decode method which
  ///   has the same signature as this type. The CipherFormats get these
  ///   encode/decode methods passed to do their work.
  /// </summary>
  /// <param name="Source">
  ///   Contains the data to be encoded or decoded
  /// </param>
  /// <param name="Dest">
  ///   Contains the data after encoding or decoding
  /// </param>
  /// <param name="DataSize">
  ///   Number of bytes to encode or decode
  /// </param>
  TDECCipherCodeEvent = procedure(const Source; var Dest; DataSize: Integer) of object;

  /// <summary>
  ///   Class type of the cipher base class, relevant for the class registration
  /// </summary>
  TDECCipherClass = class of TDECCipher;

  /// <summary>
  ///   Base class for all implemented cipher algorithms
  /// </summary>
  /// <remarks>
  ///   When adding new block ciphers do never directly inherit from this class!
  ///   Inherit from TDECCipherFormats.
  /// </remarks>
  TDECCipher = class(TDECObject)
  strict private
    /// <summary>
    ///   This is the complete memory block containing FInitializationVector,
    ///   FFeedback, FBuffer and FAdditionalBuffer
    /// </summary>
    FData     : PUInt8Array;
    /// <summary>
    ///   This is the size of FData in byte
    /// </summary>
    FDataSize : Integer;
  private
    procedure SetPaddingMode(const Value: TPaddingMode);
  strict protected
    /// <summary>
    ///   Block chaining mode used to concatenate/connect blocks in a block cipher
    /// </summary>
    FMode     : TCipherMode;
    /// <summary>
    ///   Padding mode can be used for filling up an incomplete last block in a block cipher
    /// </summary>
    FPaddingMode : TPaddingMode;
    /// <summary>
    ///   Current processing state
    /// </summary>
    FState: TCipherState;
    /// <summary>
    ///   Size of the internally used processing buffer in byte
    /// </summary>
    FBufferSize: Integer;
    /// <summary>
    ///   At which position of the buffer are we currently operating?
    /// </summary>
    FBufferIndex: Integer;

    /// <summary>
    ///   Some algorithms, mostly the cipher mode ones, need a temporary buffer
    ///   to work with. Some other methods like Done or Valid cipher need to pass
    ///   a buffer as parameter as that is ecpected by the called method.
    ///   If Done was called, FBuffer contains a C-MAC which is the encryption
    ///   of the last block concatention feedback.
    /// </summary>
    FBuffer: PUInt8Array;

    /// <summary>
    ///   Initialization vector. When using cipher modes to derive a stream
    ///   cipher from a block cipher algorithm some data from each encrypted block
    ///   is fed into the encryption of the next block. For the first block there
    ///   is no such encrypted data yet, so this initialization vector fills this
    ///   "gap".
    /// </summary>
    FInitializationVector: PUInt8Array;

    /// <summary>
    ///   Size of the initialization vector in byte. Required for algorithms
    ///   like GCM.
    /// </summary>
    FInitVectorSize: Integer;

    /// <summary>
    ///   Cipher modes are used to derive a stream cipher from block cipher
    ///   algorithms. For this something from the last entrypted block (or for
    ///   the first block from the vector) is used in the encryption of the next
    ///   block. It may be XORed with the next block cipher text for isntance.
    ///   That data "going into the next block encryption" is this feedback array
    /// </summary>
    FFeedback: PUInt8Array;

    /// <summary>
    ///   Size of FAdditionalBuffer in Byte
    /// </summary>
    FAdditionalBufferSize: Integer;
    /// <summary>
    ///   A buffer some of the cipher algorithms need to operate on. It is
    ///   some part of FBuffer like FInitializationVector and FFeedback as well.
    /// </summary>
    FAdditionalBuffer: Pointer;

    /// <summary>
    ///   If a user does not specify an init vector (IV) during key setup
    ///   (IV length = 0) the init method generates an IV by encrypting the
    ///   complete memory reserved for IV. Within this memory block is the memory
    ///   FAdditionalBuffer points to as well, and for some algorithms this part
    ///   of the memory may not be altered during initialization so it is
    ///   backupped to this memory location and restored after the IV got encrypted.
    ///   In Done it needs to be restored as well to prevent any unwanted
    ///   leftovers which might pose a security issue.
    /// </summary>
    FAdditionalBufferBackup: Pointer;

    /// <summary>
    ///   Checks whether the state machine is in one of the states specified as
    ///   parameter. If not a EDECCipherException will be raised.
    /// </summary>
    /// <param name="States">
    ///   List of states the state machine should be at currently
    /// </param>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the state machine is not in one of the states
    ///   specified by the <c>States</c> parameter.
    /// </exception>
    procedure CheckState(States: TCipherStates);

    /// <summary>
    ///   Initialize the key, based on the key passed in. This is called before
    ///   OnAfterInitVectorInitialization is called.
    /// </summary>
    /// <param name="Key">
    ///   Encryption/Decryption key to be used
    /// </param>
    /// <param name="Size">
    ///   Size of the key passed in bytes.
    /// </param>
    procedure DoInit(const Key; Size: Integer); virtual; abstract;

    /// <summary>
    ///   Assignes the right padding class to the class type field. Used only
    ///   from DECCipherFormats downwards.
    /// </summary>
    procedure InitPaddingClass; virtual; abstract;
    /// <summary>
    ///   Allows to run code after the initialization vector has been initialized
    ///   inside the Init call, which is after DoInit has been called.
    /// </summary>
    /// <param name="OriginalInitVector">
    ///   Value of the init vector as originally passed to the Init call without
    ///   any initialization steps done to/on it
    /// </param>
    procedure OnAfterInitVectorInitialization(const OriginalInitVector: TBytes); virtual; abstract;

    /// <summary>
    ///   This abstract method needs to be overwritten by each concrete encryption
    ///   algorithm as this is the routine used internally to encrypt a single
    ///   block of data.
    /// </summary>
    /// <param name="Source">
    ///   Data to be encrypted
    /// </param>
    /// <param name="Dest">
    ///   In this memory the encrypted result will be written
    /// </param>
    /// <param name="Size">
    ///   Size of source in byte
    /// </param>
    procedure DoEncode(Source, Dest: Pointer; Size: Integer); virtual; abstract;
    /// <summary>
    ///   This abstract method needs to be overwritten by each concrete encryption
    ///   algorithm as this is the routine used internally to decrypt a single
    ///   block of data.
    /// </summary>
    /// <param name="Source">
    ///   Data to be decrypted
    /// </param>
    /// <param name="Dest">
    ///   In this memory the decrypted result will be written
    /// </param>
    /// <param name="Size">
    ///   Size of source in byte
    /// </param>
    procedure DoDecode(Source, Dest: Pointer; Size: Integer); virtual; abstract;
    /// <summary>
    ///   Securely fills the processing buffer with zeroes to make stealing data
    ///   from memory harder.
    /// </summary>
    procedure SecureErase; virtual;

    /// <summary>
    ///   Returns the currently set block chaining mode, means how blocks are
    ///   linked to each other in order to avoid certain attacks.
    /// </summary>
    function GetMode: TCipherMode;

    /// <summary>
    ///   Sets the cipher mode, means how each block is being linked with his
    ///   predecessor to avoid certain attacks
    /// </summary>
    procedure SetMode(Value: TCipherMode);
    /// <summary>
    ///   When setting a mode it might need to be initialized and that can
    ///   usually only be done in a child class.
    /// </summary>
    procedure InitMode; virtual; abstract;
  public
    /// <summary>
    ///   List of registered DEC classes. Key is the Identity of the class.
    /// </summary>
    class var ClassList : TDECClassList;

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
    /// <exception cref="EDECClassNotRegisteredException">
    ///   Exception raised if the class specified by <c>Name</c> is not found
    /// </exception>
    class function ClassByName(const Name: string): TDECCipherClass;

    /// <summary>
    ///   Tries to find a class type by its numeric identity DEC assigned to it.
    ///   Useful for file headers, so they can easily encode numerically which
    ///   cipher class was being used.
    /// </summary>
    /// <param name="Identity">
    ///   Identity to look for
    /// </param>
    /// <returns>
    ///   Returns the class type of the class with the specified identity value
    ///   or throws an EDECClassNotRegisteredException exception if no class
    ///   with the given identity has been found
    /// </returns>
    /// <exception cref="EDECClassNotRegisteredException">
    ///   Exception raised if the class specified by <c>Identity</c> is not found
    /// </exception>
    class function ClassByIdentity(Identity: Int64): TDECCipherClass;

    /// <summary>
    ///   Provides meta data about the cipher algorithm used like key size.
    ///   To be overidden in the concrete cipher classes.
    /// </summary>
    /// <remarks>
    ///   C++ does not support virtual static functions thus the base cannot be
    ///   marked 'abstract'. Calling this version of the method will lead to an
    ///   EDECAbstractError
    /// </remarks>
    class function Context: TCipherContext; virtual;

    /// <summary>
    ///   Initializes the instance. Relies in parts on information given by the
    ///   Context class function.
    /// </summary>
    constructor Create; override;
    /// <summary>
    ///   Frees internal structures and where necessary does so in a save way so
    ///   that data in those structures cannot be "stolen". It removes the key
    ///   from RAM.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    ///   Provides information whether the selected block concatenation mode
    ///   provides authentication functionality or not.
    /// </summary>
    /// <returns>
    ///   true if the selected block mode is one providing authentication features
    ///   as well
    /// </returns>
    function IsAuthenticated: Boolean;

    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="Size">
    ///   Size of the key in bytes
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IVectorSize">
    ///   Size of the initialization vector in bytes
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key; Size: Integer; const IVector; IVectorSize: Integer; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: TBytes; const IVector: TBytes; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: RawByteString; const IVector: RawByteString = '';
      IFiller: Byte = $FF; PaddingMode: TPaddingMode = pmNone); overload;
    {$IFDEF ANSISTRINGSUPPORTED}
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key.
    ///   Only for use with the classic desktop compilers.
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: AnsiString; const IVector: AnsiString = '';
                   IFiller: Byte = $FF;  PaddingMode: TPaddingMode = pmNone); overload;
    {$ENDIF}
    {$IFNDEF NEXTGEN}
    /// <summary>
    ///   Initializes the cipher with the necessary encryption/decryption key.
    ///   Only for use with the classic desktop compilers.
    /// </summary>
    /// <param name="Key">
    ///   Encryption/decryption key. Recommended/required key length is dependant
    ///   on the concrete algorithm.
    /// </param>
    /// <param name="IVector">
    ///   Initialization vector. This contains the values the first block of
    ///   data to be processed is linked with. This is being done the same way
    ///   as the 2nd block of the data to be processed will be linked with the
    ///   first block and so on and this is dependant on the cypher mode set via
    ///   Mode property
    /// </param>
    /// <param name="IFiller">
    ///   Optional parameter defining the value with which the initialization
    ///   vector is prefilled. So it will contain something defined in any unused
    ///   bytes if a value shorter than the required IV size is given for the IV.
    /// </param>
    /// <param name="PaddingMode">
    ///   optional parameter defining the padding mode instead of using IFiller byte.
    /// </param>
    procedure Init(const Key: WideString; const IVector: WideString = ''; IFiller: Byte = $FF;
      PaddingMode: TPaddingMode = pmNone); overload;
    {$ENDIF}

    /// <summary>
    ///   Properly finishes the cryptographic operation. It needs to be called
    ///   at the end of encrypting or decrypting data. It does NOT remove the
    ///   keys from RAM (this will be done in the destruction only).
    ///   You can continue encrypting/decrypting without calling Init() again.
    /// </summary>
    procedure Done; virtual;

    // Encoding / Decoding Routines
    // Do not add further methods of that kind here! If needed add them to
    // TDECFormattedCipher in DECCipherFormats or inherit from that one.

    /// <summary>
    ///   Encrypts the contents of a RawByteString. This method is deprecated
    ///   and should be replaced by a variant expecting TBytes as source in
    ///   order to not support mistreating strings as binary buffers.
    /// </summary>
    /// <remarks>
    ///   This is the direct successor of the EncodeBinary method from DEC 5.2.
    ///   When block chaining mode ECBx is used
    ///   (not recommended!), the size of the data passed via this parameter
    ///   needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
    /// </remarks>
    /// <param name="Source">
    ///   The data to be encrypted
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. Here a formatting method can be passed. The
    ///   resulting encrypted data will be formatted with this function, if one
    ///   has been passed. Examples are hex or base 64 formatting.
    /// </param>
    /// <returns>
    ///   Encrypted data. Init must have been called previously.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeRawByteString(const Source: RawByteString;
                                 Format: TDECFormatClass = nil): RawByteString;
                                 deprecated 'please use EncodeBytes functions or TCipherFormats.EncodeStringToString now';
    /// <summary>
    ///   Decrypts the contents of a RawByteString. This method is deprecated
    ///   and should be replaced by a variant expecting TBytes as source in
    ///   order to not support mistreating strings as binary buffers.
    /// </summary>
    /// <remarks>
    ///   This is the direct successor of the DecodeBinary method from DEC 5.2
    ///   When block chaining mode ECBx is used
    ///   (not recommended!), the size of the data passed via this parameter
    ///   needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
    /// </remarks>
    /// <param name="Source">
    ///   The data to be decrypted
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. Here a formatting method can be passed. The
    ///   data to be decrypted will be formatted with this function, if one
    ///   has been passed. Examples are hex or base 64 formatting.
    ///   This is used for removing a formatting applied by the EncodeRawByteString
    ///   method.
    /// </param>
    /// <returns>
    ///   Decrypted data. Init must have been called previously.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeRawByteString(const Source: RawByteString;
                                 Format: TDECFormatClass = nil): RawByteString; deprecated 'please use DecodeBytes functions now';

    /// <summary>
    ///   Encrypts the contents of a ByteArray.
    /// </summary>
    /// <param name="Source">
    ///   The data to be encrypted. When block chaining mode ECBx is used
    ///   (not recommended!), the size of the data passed via this parameter
    ///   needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. Here a formatting method can be passed. The
    ///   resulting encrypted data will be formatted with this function, if one
    ///   has been passed. Examples are hex or base 64 formatting.
    /// </param>
    /// <returns>
    ///   Encrypted data. Init must have been called previously.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function EncodeBytes(const Source: TBytes; Format: TDECFormatClass = nil): TBytes;
    /// <summary>
    ///   Decrypts the contents of a ByteArray.
    /// </summary>
    /// <param name="Source">
    ///   The data to be decrypted. When block chaining mode ECBx is used
    ///   (not recommended!), the size of the data passed via this parameter
    ///   needs to be a multiple of the block size of the algorithm used,
    ///   otherwise a EDECCipherException exception will be raised!
    /// </param>
    /// <param name="Format">
    ///   Optional parameter. Here a formatting method can be passed. The
    ///   data to be decrypted will be formatted with this function, if one
    ///   has been passed. Examples are hex or base 64 formatting.
    ///   This is used for removing a formatting applied by the EncodeRawByteString
    ///   method.
    /// </param>
    /// <returns>
    ///   Decrypted data. Init must have been called previously.
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised if the length of the data passed as <c>Source</c>
    ///   is not a multiple of the algorithm's block size.
    /// </exception>
    function DecodeBytes(const Source: TBytes; Format: TDECFormatClass): TBytes;

    /// <summary>
    ///   Calculates a Cipher-based message authentication code (CMAC).
    ///   This is the encryption of the last block concatenation feedback value.
    ///   In decryption scenarios it can be used to check if the data arrived
    ///   unaltered if the sender provides the MAC value along with the encrypted
    ///   text. Both need to match after decrypting. Using this method is less
    ///   secure than using the HMAC algorithm!
    ///   This method cannot be used in the ECB cipher mode.
    ///   Side effect: "Done" will be called if it hasn't been called before.
    /// </summary>
    /// <param name="Format">
    ///   Optional parameter. Here a formatting method can be passed. The
    ///   data to be decrypted will be formatted with this function, if one
    ///   has been passed. Examples are hex or base 64 formatting.
    ///   This is used for removing a formatting applied by the EncodeRawByteString
    ///   method.
    /// </param>
    /// <returns>
    ///   Calculates a Cipher-based message authentication code (CMAC).
    /// </returns>
    /// <exception cref="EDECCipherException">
    ///   Exception raised the cipher mode is ECB.
    /// </exception>
    { TODO: Add unit test }
    function CalcMAC(Format: TDECFormatClass = nil): RawByteString;

    /// Same as CalcMAC, but return TBytes
    function CalcMACBytes(Format: TDECFormatClass = nil): TBytes;

    // properties

    /// <summary>
    ///   Provides the size of the initialization vector in bytes.
    /// </summary>
    property InitVectorSize: Integer
      read   FBufferSize;
    /// <summary>
    ///   Provides access to the contents of the initialization vector
    /// </summary>
    property InitVector: PUInt8Array
      read   FInitializationVector;

    /// <summary>
    ///   Cipher modes are used to derive a stream cipher from block cipher
    ///   algorithms. For this something from the last entrypted block (or for
    ///   the first block from the vector) is used in the encryption of the next
    ///   block. It may be XORed with the next block cipher text for instance.
    ///   That data "going into the next block encryption" is stored in this
    ///   feedback array. The size usually depends on the block size of the
    ///   cipher algorithm.
    /// </summary>
    property Feedback: PUInt8Array
      read   FFeedback;
    /// <summary>
    ///   Allows to query the current internal processing state
    /// </summary>
    property State: TCipherState
      read   FState;
    /// <summary>
    ///   Mode used for padding data to be encrypted/decrypted. See TCipherMode.
    /// </summary>
    property Mode: TCipherMode
      read   GetMode
      write  SetMode;

    /// <summary>
    ///   Mode used for filling up an incomplete last block in a block cipher
    /// </summary>
    property PaddingMode: TPaddingMode
      read   FPaddingMode
      write  SetPaddingMode;
  end;

/// <summary>
///   Returns the passed cipher class type if it is not nil. Otherwise the
///   class type class set per SetDefaultCipherClass is being returned. If using
///   the DECCiphers unit that one registers TCipher_Null in the initialization
/// </summary>
/// <param name="CipherClass">
///   Class type of a cipher class like TCipher_Blowfish or nil, if no
///   encryption/decryption is desired.
/// </param>
/// <returns>
///   Passed class type or defined default cipher class type, depending on
///   CipherClass parameter value.
/// </returns>
function ValidCipher(CipherClass: TDECCipherClass = nil): TDECCipherClass;

/// <summary>
///   Defines which cipher class to return by ValidCipher if passing nil to that
/// </summary>
/// <param name="CipherClass">
///   Class type of a cipher class to return by ValidCipher if passing nil to
///   that one. This parameter should not be nil!
/// </param>
procedure SetDefaultCipherClass(CipherClass: TDECCipherClass);

/// <summary>
///   Provides information whether a certain block concatenation mode
///   provides authentication functionality or not.
/// </summary>
/// <param name="BlockMode">
///   Block mode to check fo authentication features
/// </param>
/// <returns>
///   true if the selected block mode is one providing authentication features
///   as well
/// </returns>
function IsAuthenticatedBlockMode(BlockMode: TCipherMode): Boolean;

implementation

uses
  {$IFDEF FPC}
  TypInfo,
  {$ELSE}
  System.TypInfo,
  {$ENDIF}
  DECUtil;

{$IFOPT Q+}{$DEFINE RESTORE_OVERFLOWCHECKS}{$Q-}{$ENDIF}
{$IFOPT R+}{$DEFINE RESTORE_RANGECHECKS}{$R-}{$ENDIF}

resourcestring
  sAlreadyPadded        = 'Cipher has already been padded, cannot process message';
  sInvalidState         = 'Cipher is not in valid state for this action';
  sNoKeyMaterialGiven   = 'No Keymaterial given (Security Issue)';
  sKeyMaterialTooLarge  = 'Keymaterial is too large for use (Security Issue)';
  sIVMaterialTooLarge   = 'Initvector is too large for use (Security Issue)';
  sInvalidMACMode       = 'Invalid Cipher mode to compute MAC';
  sCipherNoDefault      = 'No default cipher has been registered';
  sInvalidUseOfPadding  = 'No padding for stream cipher allowed';

var
  /// <summary>
  ///   Cipher class returned by ValidCipher if nil is passed as parameter to it
  /// </summary>
  FDefaultCipherClass: TDECCipherClass = nil;

function ValidCipher(CipherClass: TDECCipherClass): TDECCipherClass;
begin
  if CipherClass <> nil then
    Result := CipherClass
  else
    Result := FDefaultCipherClass;

  if Result = nil then
    raise EDECCipherException.CreateRes(@sCipherNoDefault);
end;

procedure SetDefaultCipherClass(CipherClass: TDECCipherClass);
begin
  Assert(Assigned(CipherClass), 'Do not set a nil default cipher class!');

  FDefaultCipherClass := CipherClass;
end;

function IsAuthenticatedBlockMode(BlockMode: TCipherMode): Boolean;
begin
  Result := BlockMode = cmGCM;
end;

{ TDECCipher }

constructor TDECCipher.Create;
var
  MustAdditionalBufferSave: Boolean;
begin
  inherited Create;

  FBufferSize              := Context.BufferSize;
  FAdditionalBufferSize    := Context.AdditionalBufferSize;
  MustAdditionalBufferSave := Context.NeedsAdditionalBufferBackup;

  // Initialization vector, feedback, buffer, additional buffer
  FDataSize := FBufferSize * 3 + FAdditionalBufferSize;

  if MustAdditionalBufferSave then
    // if contents of the FAdditionalBuffer needs to be saved increase buffer size
    // by FAdditionalBufferSize so FAdditionalBuffer and then FAdditionalBufferBackup
    // fit in the buffer
    Inc(FDataSize, FAdditionalBufferSize);

  // ReallocMemory instead of ReallocMem due to C++ compatibility as per 10.1 help
  FData                 := ReallocMemory(FData, FDataSize);
  FInitializationVector := @FData[0];
  FInitVectorSize       := 0;
  FFeedback             := @FInitializationVector[FBufferSize];
  FBuffer               := @FFeedback[FBufferSize];
  FAdditionalBuffer     := @FBuffer[FBufferSize];

  if MustAdditionalBufferSave then
    // buffer contents: FData, then FFeedback, then FBuffer then FAdditionalBuffer
    FAdditionalBufferBackup := @PUInt8Array(FAdditionalBuffer)[FAdditionalBufferSize]
  else
    FAdditionalBufferBackup := nil;

  self.PaddingMode := pmNone;
  FState           := csNew;

  SecureErase;
end;

destructor TDECCipher.Destroy;
begin
  SecureErase;
  // FreeMem instead of ReallocMemory which produced a memory leak. ReallocMemory
  // was used instead of ReallocMem due to C++ compatibility as per 10.1 help
  FreeMem(FData, FDataSize);
  FInitializationVector   := nil;
  FFeedback               := nil;
  FBuffer                 := nil;
  FAdditionalBuffer       := nil;
  FAdditionalBufferBackup := nil;
  inherited Destroy;
end;

procedure TDECCipher.SetMode(Value: TCipherMode);
begin
  if Value <> FMode then
  begin
    if not (FState in [csNew, csInitialized, csDone]) then
      Done;

    FMode := Value;
    InitMode;
  end;
end;

procedure TDECCipher.SetPaddingMode(const Value: TPaddingMode);
begin
  FPaddingMode := Value;
  InitPaddingClass;
end;

procedure TDECCipher.CheckState(States: TCipherStates);
begin
  if not (FState in States) then
  begin
    if FState = csPadded then
      raise EDECCipherException.CreateRes(@sAlreadyPadded)
    else
      raise EDECCipherException.CreateRes(@sInvalidState);
  end;
end;

class function TDECCipher.ClassByIdentity(Identity: Int64): TDECCipherClass;
begin
  result := TDECCipherClass(ClassList.ClassByIdentity(Identity));
end;

class function TDECCipher.ClassByName(const Name: string): TDECCipherClass;
begin
  result := TDECCipherClass(ClassList.ClassByName(Name));
end;

class function TDECCipher.Context: TCipherContext;
begin
  // C++ does not support virtual static functions thus the base cannot be
  // marked 'abstract'. This is our workaround:
  raise EDECAbstractError.Create(GetShortClassName);
end;

procedure TDECCipher.Init(const Key; Size: Integer; const IVector;
                          IVectorSize: Integer; IFiller: Byte;
                          PaddingMode: TPaddingMode);
var
  OriginalInitVector : TBytes;
begin
  FState          := csNew;
  FInitVectorSize := IVectorSize;

  // stream ciphers have no padding modes
  if (PaddingMode <> pmNone) and (ctStream in Context.CipherType) then
    raise EDECCipherException.CreateRes(@sInvalidUseOfPadding);
  self.PaddingMode := PaddingMode;

  SecureErase;

  if (Size > Context.KeySize) and (not (ctNull in Context.CipherType)) then
    raise EDECCipherException.CreateRes(@sKeyMaterialTooLarge);

  if (FInitVectorSize > FBufferSize) and (not (FMode = cmGCM)) then
    raise EDECCipherException.CreateRes(@sIVMaterialTooLarge);

  DoInit(Key, Size);
  if FAdditionalBufferBackup <> nil then
    // create backup of FBuffer
    Move(FAdditionalBuffer^, FAdditionalBufferBackup^, FAdditionalBufferSize);

  FillChar(FInitializationVector^, FBufferSize, IFiller);

  SetLength(OriginalInitVector, IVectorSize);
  if (IVectorSize > 0) then
    Move(IVector, OriginalInitVector[0], IVectorSize);

  // GCM needs same treatment of empty IV even if IV specified
  if (IVectorSize = 0) or (FMode = cmGCM) then
  begin
    DoEncode(FInitializationVector, FInitializationVector, FBufferSize);
    if FAdditionalBufferBackup <> nil then
      // Restore backup fo FBuffer
      Move(FAdditionalBufferBackup^, FAdditionalBuffer^, FAdditionalBufferSize);
  end
  else
    Move(IVector, FInitializationVector^, IVectorSize);

  OnAfterInitVectorInitialization(OriginalInitVector);

  Move(FInitializationVector^, FFeedback^, FBufferSize);

  FState := csInitialized;
end;

procedure TDECCipher.Init(const Key     : TBytes;
                          const IVector : TBytes;
                          IFiller       : Byte;
                          PaddingMode   : TPaddingMode);
begin
  // GCM allows empty key as the authentication still works
  if (Length(Key) = 0) and (not (ctNull in Context.CipherType)) and
     (not (FMode = cmGCM)) and (Context.KeySize > 0) then
    raise EDECCipherException.CreateRes(@sNoKeyMaterialGiven);

  if IVector <> nil then
    Init(Key[0], Length(Key), IVector[0], Length(IVector), IFiller, PaddingMode)
  else
    Init(Key[0], Length(Key), NullStr, 0, IFiller, PaddingMode);
end;

procedure TDECCipher.Init(const Key     : RawByteString;
                          const IVector : RawByteString;
                          IFiller       : Byte;
                          PaddingMode   : TPaddingMode);
begin
  // GCM allows empty key as the authentication still works
  if (Length(Key) = 0) and (not (ctNull in Context.CipherType)) and
     (not (FMode = cmGCM)) and (Context.KeySize > 0) then
    raise EDECCipherException.CreateRes(@sNoKeyMaterialGiven);

  if Length(IVector) > 0 then
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Init(Key[Low(Key)], Length(Key) * SizeOf(Key[Low(Key)]),
         IVector[Low(IVector)], Length(IVector) * SizeOf(IVector[Low(IVector)]),
         IFiller, PaddingMode)
    {$ELSE}
    Init(Key[1], Length(Key) * SizeOf(Key[1]),
         IVector[1], Length(IVector) * SizeOf(IVector[1]), IFiller, PaddingMode)
    {$ENDIF}
  else
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Init(Key[Low(Key)], Length(Key) * SizeOf(Key[Low(Key)]), NullStr, 0, IFiller,
      PaddingMode);
    {$ELSE}
    Init(Key[1], Length(Key) * SizeOf(Key[1]), NullStr, 0, IFiller, PaddingMode);
    {$ENDIF}
end;


{$IFDEF ANSISTRINGSUPPORTED}
procedure TDECCipher.Init(const Key, IVector: AnsiString;
                          IFiller: Byte;
                          PaddingMode: TPaddingMode);
begin
  // GCM allows empty key as the authentication still works
  if (Length(Key) = 0) and (not (ctNull in Context.CipherType)) and
     (not (FMode = cmGCM)) and (Context.KeySize > 0) then
    raise EDECCipherException.Create(sNoKeyMaterialGiven);

  if Length(IVector) > 0 then
    {$IF CompilerVersion >= 24.0}
    Init(Key[Low(Key)], Length(Key) * SizeOf(Key[Low(Key)]),
         IVector[Low(IVector)], Length(IVector) * SizeOf(Low(IVector)),
         IFiller, PaddingMode)
    {$ELSE}
    Init(Key[1], Length(Key) * SizeOf(Key[Low(Key)]),
         IVector[IVector[1]], Length(IVector) * SizeOf(IVector[1]), IFiller,
         PaddingMode)
    {$IFEND}
  else
    {$IF CompilerVersion >= 24.0}
    Init(Key[Low(Key)], Length(Key) * SizeOf(Key[Low(Key)]), NullStr, 0, IFiller,
         PaddingMode);
    {$ELSE}
    Init(Key[1], Length(Key) * SizeOf(Key[1]), NullStr, 0, IFiller, PaddingMode);
    {$IFEND}
end;
{$ENDIF}


{$IFNDEF NEXTGEN}
procedure TDECCipher.Init(const Key, IVector : WideString;
                          IFiller            : Byte;
                          PaddingMode        : TPaddingMode);
begin
  // GCM allows empty key as the authentication still works
  if (Length(Key) = 0) and (not (ctNull in Context.CipherType)) and
     (not (FMode = cmGCM)) and (Context.KeySize > 0) then
    raise EDECCipherException.CreateRes(@sNoKeyMaterialGiven);

  if Length(IVector) > 0 then
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Init(Key[Low(Key)], Length(Key) * SizeOf(Key[Low(Key)]),
         IVector[Low(IVector)], Length(IVector) * SizeOf(IVector[Low(IVector)]),
         IFiller, PaddingMode)
    {$ELSE}
    Init(Key[1], Length(Key) * SizeOf(Key[1]),
         IVector[1], Length(IVector) * SizeOf(IVector[1]), IFiller, PaddingMode)
    {$ENDIF}
  else
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    Init(Key[Low(Key)], Length(Key) * SizeOf(Key[Low(Key)]), NullStr, 0, IFiller,
         PaddingMode);
    {$ELSE}
    Init(Key[1], Length(Key) * SizeOf(Key[1]), NullStr, 0, IFiller, PaddingMode);
    {$ENDIF}
end;
{$ENDIF}

function TDECCipher.IsAuthenticated: Boolean;
begin
  Result := IsAuthenticatedBlockMode(FMode);
end;

procedure TDECCipher.Done;
begin
  if FState <> csDone then
  begin
    FState := csDone;
    FBufferIndex := 0;
    DoEncode(FFeedback, FBuffer, FBufferSize);
    Move(FInitializationVector^, FFeedback^, FBufferSize);
    if FAdditionalBufferBackup <> nil then
      Move(FAdditionalBufferBackup^, FAdditionalBuffer^, FAdditionalBufferSize);
  end;
end;

procedure TDECCipher.SecureErase;
begin
  ProtectBuffer(FData[0], FDataSize);
end;

function TDECCipher.EncodeRawByteString(const Source: RawByteString; Format: TDECFormatClass): RawByteString;
var
  b : TBytes;
begin
  SetLength(b, 0);
  if Length(Source) > 0 then
  begin
    {$IFDEF HAVE_STR_LIKE_ARRAY}
    SetLength(b, Length(Source) * SizeOf(Source[Low(Source)]));
    DoEncode(@Source[low(Source)], @b[0], Length(Source) * SizeOf(Source[low(Source)]));
    {$ELSE}
    SetLength(b, Length(Source) * SizeOf(Source[1]));
    DoEncode(@Source[1], @b[0], Length(Source) * SizeOf(Source[1]));
    {$ENDIF}
    Result := BytesToRawString(ValidFormat(Format).Encode(b));
  end;
end;

function TDECCipher.GetMode: TCipherMode;
begin
  Result := FMode;
end;

function TDECCipher.EncodeBytes(const Source: TBytes; Format: TDECFormatClass = nil): TBytes;
begin
  SetLength(Result, 0);
  if Length(Source) > 0 then
  begin
    SetLength(Result, Length(Source) * SizeOf(Source[0]));
    DoEncode(@Source[0], @Result[0], Length(Source) * SizeOf(Source[0]));
    Result := ValidFormat(Format).Encode(Result);
  end;
end;

function TDECCipher.DecodeRawByteString(const Source: RawByteString; Format: TDECFormatClass): RawByteString;
var
  b : TBytes;
begin
  SetLength(Result, 0);
  if Length(Source) > 0 then
  begin
    // Delphi 10.1 Berlin and 10.2 Tokyo will issue a W1057 implicit string
    // conversion warning here because the RawByteString BytesOf function is by
    // mistake in a $IFNDEF NEXTGEN block. See QP report:
    // https://quality.embarcadero.com/browse/RSP-20574
    // This has been fixed in 10.3.0 Rio
    b := ValidFormat(Format).Decode(BytesOf(Source));

    SetLength(Result, Length(b));

    {$IFDEF HAVE_STR_LIKE_ARRAY}
    DoDecode(@b[0], @Result[Low(Result)], Length(Result) * SizeOf(Result[Low(Result)]));
    {$ELSE}
    DoDecode(@b[0], @Result[1], Length(Result) * SizeOf(Result[1]));
    {$ENDIF}
  end;
end;

function TDECCipher.DecodeBytes(const Source: TBytes; Format: TDECFormatClass): TBytes;
begin
  SetLength(Result, 0);
  if Length(Source) > 0 then
  begin
    Result := ValidFormat(Format).Decode(Source);
    DoDecode(@Result[0], @Result[0], Length(Result) * SizeOf(Result[0]));
  end;
end;

function TDECCipher.CalcMAC(Format: TDECFormatClass): RawByteString;
begin
  Done; { TODO: This might be considered as unwanted side effect. Maybe we should instead raise an Exception if State is not csDone instead? This would also "teach" the user to don't forget to call "Done". }
  if FMode in [cmECBx] then
    raise EDECException.CreateRes(@sInvalidMACMode)
  else
    Result := ValidFormat(Format).Encode(FBuffer^, FBufferSize);
end;

function TDECCipher.CalcMACBytes(Format: TDECFormatClass): TBytes;
begin
  Result := System.SysUtils.BytesOf(CalcMAC);
end;

{$IFDEF RESTORE_RANGECHECKS}{$R+}{$ENDIF}
{$IFDEF RESTORE_OVERFLOWCHECKS}{$Q+}{$ENDIF}

{$IFDEF DELPHIORBCB}
procedure ModuleUnload(Instance: NativeUInt);
var // automaticaly deregistration/releasing
  i: Integer;
  Items: TArray<TPair<Int64, TDECCLass>>;
begin
  // C++Builder calls this function for our own module, but we destroy the ClassList
  // in that case in the finalization section anyway.
  if (Instance <> HInstance) and
     (TDECCipher.ClassList <> nil) and (TDECCipher.ClassList.Count > 0) then
  begin
    Items := TDECCipher.ClassList.ToArray;
    for i := Length(Items) - 1 downto 0 do
    begin
      if FindClassHInstance(Items[i].Value) = HINST(HInstance) then
        TDECCipher.ClassList.Remove(Items[i].Key);
    end;
  end;
end;
{$ENDIF DELPHIORBCB}

initialization
  // Code for packages and dynamic extension of the class registration list
  {$IFDEF DELPHIORBCB}
  AddModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}

  TDECCipher.ClassList := TDECClassList.Create;

finalization
  // Ensure no further instances of classes registered in the registraiotn list
  // are possible through the list after this unit has been unloaded by unloding
  // the package this unit is in
  {$IFDEF DELPHIORBCB}
  RemoveModuleUnloadProc(ModuleUnload);
  {$ENDIF DELPHIORBCB}

  TDECCipher.ClassList.Free;
end.
