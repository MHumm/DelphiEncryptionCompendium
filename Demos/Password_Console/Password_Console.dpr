{*****************************************************************************
  The DEC team (see file NOTICE.txt) licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the license. A copy of this licence is found in the root directory of
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
///   Some demonstrations of how to use the password hashing classes
/// </summary>
program Password_Console;

{$APPTYPE CONSOLE}

{$R *.res}

uses
  System.SysUtils,
  DECHashAuthentication,
  DECHash,
  DECTypes,
  DECFormat;

var
  HashInst  : THash_BCrypt;
  HashInst2 : TDECPasswordHash;
  HashRef   : TDECPasswordHashClass;
  Result    : Boolean;
  Password  : string;

begin
  HashInst := THash_BCrypt.Create;
  try
    try
      // manually calculate the password hash using the BCrypt algorithm

      // Cost defines how many rounds are used, the higher the stronger.
      // See MinCost and MaxCost methods as well.
      HashInst.Cost := 6;
      // Salt for BCrypt must always be 16 byte long.
      HashInst.Salt := [$2a, $1f, $1d, $c7, $0a, $3d, $14, $79,
                        $56, $a4, $6f, $eb, $e3, $01, $60, $17];
      // Calculate the hash for password 'abc' and display it in hexadecimal
      WriteLn('Hash for password abc is:');
      WriteLn(HashInst.CalcString('abc', TFormat_HEXL));
      WriteLn;

      // Generate a Crypt/BSD style password entry. The BSD operating system
      // stores his password records in this format. More information about the
      // format in the XMLDOC of the TDECHash_Authentication and THash_BCrypt
      // classes.
      // The formatting class TFormat_BCryptBSD must be passed here, as this
      // avoids dragging the TDECFormat unit into DECHashAuthentication and
      // DECHash units just for a case not everybody needs. The right output
      // is: '$2a$06$If6bvum7DFjUnE9p2uDeDu0YHzrHM6tf.iqN8.yx.jNN1ILEf7h0i'
      WriteLn('Crypt/BSD data for password abc is:');
      WriteLn(HashInst.GetDigestInCryptFormat('abc',
                                              '6',
                                              'If6bvum7DFjUnE9p2uDeDu',
                                              false,
                                              TFormat_BCryptBSD));
      WriteLn;

      // Check some entered password
      WriteLn('Enter correct password to continue (correct value is: GoOn!):');

      repeat
        ReadLn(Password);
        // the data against which the entered password is compared is given
        // in Crypt/BSD style format, esp. in the BCrypt variant of that format
        Result := HashInst.IsValidPassword(Password,
                                           '$2a$06$If6bvum7DFjUnE9p2uDeDuJZX' +
                                           '1LXp30kMOn/QEnf4laWZvcLxd0iK',
                                           TFormat_BCryptBSD);
        if not Result then
          WriteLn('Entered password is wrong!');
      until Result;

      WriteLn('Entered password is correct!');
      WriteLn;

      // find the class reference of the BCrypt inplementation and create an
      // object from it
      try
        HashRef := TDECPasswordHash.ClassByCryptIdentity('$2a');
        HashInst2 := HashRef.Create;
        try
          WriteLn('Class created: ' + HashInst2.ClassName);
          Result := HashInst.IsValidPassword('GoOn!',
                                             '$2a$06$If6bvum7DFjUnE9p2uDeDuJZX' +
                                             '1LXp30kMOn/QEnf4laWZvcLxd0iK',
                                             TFormat_BCryptBSD);
          WriteLn('Is right password: ' + BoolToStr(Result, true));
        finally
          HashInst2.Free;
        end;
      except
        on e:EDECClassNotRegisteredException do
          WriteLn('Algorithm implementation not found');
      end;
    except
      on E: Exception do
        Writeln(E.ClassName, ': ', E.Message);
    end;
  finally
    HashInst.Free;
  end;

  WriteLn;
  WriteLn('Press enter to quit');
  ReadLn;
end.
