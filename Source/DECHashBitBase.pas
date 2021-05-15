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

/// <summary>
///   Base unit for all the hash algorithms which can operate on bit sized
///   messsages as well.
/// </summary>
unit DECHashBitBase;

interface

{$INCLUDE DECOptions.inc}

uses
  {$IFDEF FPC}
  SysUtils, Classes,
  {$ELSE}
  System.SysUtils, System.Classes,
  {$ENDIF}
  DECHashAuthentication;

type
  /// <summary>
  ///   Base class for all hash algorithms which can operate on bit sized
  ///   messsages as well.
  /// </summary>
  TDECHashBit = class(TDECHashAuthentication)
  public
    /// <summary>
    ///   Setting this to a number of bits allows to process messages which have
    ///   a length which is not a exact multiple of bytes.
    /// </summary>
    property FinalBitLength : UInt16
      read   FFinalBitLen
      write  FFinalBitLen;
  end;

implementation

end.
