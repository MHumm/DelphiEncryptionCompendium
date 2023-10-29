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
///   Routines etc. for use with encrypted ZIP files
/// </summary>
unit DECZIPHelper;

interface

uses
  DECCiphers,
  DECCipherFormats;

  /// <summary>
  ///   Creates an instance for encrypting or decrypting the algorithm specified
  ///   by the ZIP Algorithm ID documented in chapter 7.2.3.2 found in
  ///   https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
  /// </summary>
  /// <param name="AlgorithmID">
  ///   Unique ID for a crypto algorithm as specified in the documentation
  /// </param>
  /// <returns>
  ///   Created instance of the cipher class
  /// </returns>
  /// <exception cref="EDECClassNotRegisteredException">
  ///   Exception raised if called with an unknown/unsupported AlgorithmID
  /// </exception>
  function CreateZIPCryptoAlgorithmInstance(AlgorithmID: UInt16):TDECFormattedCipher;

resourcestring
  /// <summary>
  ///   Exception text for attempts to create an instance for an unknown
  ///   algorithm ID
  /// </summary>
  rUnknownZIPAlgorithmID = 'Unknown ZIP cypher algorithm ID %0:d';

implementation

uses
  System.SysUtils,
  DECTypes,
  DECCipherBase;

function CreateZIPCryptoAlgorithmInstance(AlgorithmID: UInt16):TDECFormattedCipher;
begin
  case AlgorithmID of
    $6601 : Result := TCipher_1DES.Create;
//    $6602 : Result := TCipher_RC2.Create; // (version needed to extract < 5.2)
//                                          // This has to do with a faulty RC2
//                                          // implementation in XP SP1 and earlier
//                                          // Unsupported as we do not know the
//                                          // details of the fault
    $6603 : Result := TCipher_3DES.Create;  // 3DES 168
    $6609 : Result := TCipher_2DES.Create;  // 3DES 112
    $660E : Result := TCipher_AES128.Create;
    $660F : Result := TCipher_AES192.Create;
    $6610 : Result := TCipher_AES256.Create;
    $6702 : Result := TCipher_RC2.Create; // (version needed to extract >= 5.2)
    $6720 : Result := TCipher_Blowfish.Create;
    $6721 : Result := TCipher_Twofish.Create;
    $6801 : Result := TCipher_RC4.Create;
    $FFFF : raise EDECClassNotRegisteredException.Create(Format(rUnknownZIPAlgorithmID,
                                                                [AlgorithmID]));
    else
      raise EDECClassNotRegisteredException.Create(Format(rUnknownZIPAlgorithmID,
                                                          [AlgorithmID]));
  end;

  Result.Mode := cmCBCx; // as per ZIP documentation the only supported mode
end;

end.
