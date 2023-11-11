grammar lang;
options {
    output = AST;
    ASTLabelType = pANTLR3_BASE_TREE;
    language = C;
    backtrack = true;
}

tokens {
    Root;
    Member;
    Body;
    Signature;
    Arg;
    Array;
    Expr;
    ReturnType;
}

source: sourceItem* -> ^(Root sourceItem*);

typeSpec: 'as' typeRef arraySpec? -> ^(typeRef arraySpec?);

typeRef:
    builtin | identifier
;

arraySpec: LParen (Comma)* RParen -> ^(Array Comma*);

funcSignature: identifier LParen (argDef (Comma argDef)*)? RParen typeSpec?
    -> ^(identifier ^(Signature ^(ReturnType typeSpec)? argDef*)?);

fragment argDef: identifier typeSpec?
    -> ^(Arg identifier typeSpec);

sourceItem:
    Function funcSignature (statement* End Function)? 
        -> ^(Function ^(funcSignature ^(Body statement*)?))
    | Struct identifier member* End Struct
        -> ^(Struct ^(identifier member*)); 

fragment member: typeRef identifier Semi -> ^(Member typeRef identifier);

statement:
    Dim identifier (Comma identifier)* typeSpec -> ^(Dim ^(typeSpec identifier+))
    | If expr thenClause elseClause? End If -> ^(If expr thenClause elseClause)
    | While expr statement* Wend -> ^(While expr ^(Body statement*)?)
    | Do statement* Loop loopTerm expr -> ^(Loop ^(loopTerm expr) ^(Body statement*)?)
    | Break
    | expr Semi -> ^(Expr expr)
    | call Assignment expr Semi -> ^(Assignment call expr)
;

thenClause: Then statement* -> ^(Then statement*);
elseClause: Else statement* -> ^(Else statement*);
loopTerm: While | Until;

expr: orExpr;

unOp: Not | Minus | Tilde;
addOp: Plus | Minus;
bitOp: BitOp | Tilde;
memberAccess: MemberAccess! identifier;

orExpr: andExpr (Or^ andExpr)*;
andExpr: compExpr (And^ compExpr)*;
compExpr: addExpr (CompOp^ addExpr)*;
addExpr: multExpr (addOp^ multExpr)*;
multExpr: bitExpr (MultOp^ bitExpr)*;
bitExpr: unExpr (bitOp^ unExpr)*;
unExpr: (unOp^)? call;
call: atom (LParen (expr (Comma expr)*)? RParen)? -> ^(atom ^(LParen expr*)?);
atom:
    LParen expr RParen -> expr
    |identifier^ memberAccess?
    |literal
;

builtin: BuiltinType; 
literal: boolean|str|character|hex|bits|dec;

identifier: Identifier;
str: String; // строка, окруженная двойными кавычками 
character: CharLiteral; // одиночный символ в одинарных кавычках 
hex: HexLiteral;  // шестнадцатеричный литерал 
bits: BitsLiteral;  // битовый литерал 
dec: Integer;  // десятичный литерал 
boolean: Bool; // булевский литерал 
Struct: 'struct';
Function: 'function';
Dim: 'dim';
If: 'if';
Then: 'then';
Else: 'else';
Do: 'do';
While: 'while';
Wend: 'wend';
Break: 'break';
Loop: 'loop';
Until: 'until';
MemberAccess: '.';

End: 'end';

And: '&&';
Or: '||';
BitOp: '^' | '|' | '&';
CompOp: '>' | '<' | '<=' | '>=' | '==';
MultOp: '*' | '/' | '%';
Tilde: '~';
Not: '!';
Minus: '-';
Plus: '+';
Assignment: '=';


String: '"' Char* '"';
CharLiteral: '\'' Char '\''; // одиночный символ в одинарных кавычках 
HexLiteral: '0' ('x'|'X') HexDigit+;  // шестнадцатеричный литерал 
BitsLiteral: '0' ('b'|'B') Bit+;  // битовый литерал 
Integer: Digit+;  // десятичный литерал 
Bool: 'true'|'false'; // булевский литерал 
BuiltinType: 'bool'|'byte'|'int'|'uint'|'long'|'ulong'|'char'|'string';
Identifier: ('a'..'z' | 'A'..'Z' | '_') ('a'..'z' | 'A'..'Z' | Digit | '_')*; // идентификатор 

LParen: '(';
RParen: ')';
Comma: ',';
Semi: ';';

fragment Char: EscapeSequence | ~('\u0000'..'\u001f' | '\\' | '\"');
fragment EscapeSequence: '\\' (UnicodeEscape |'b'|'t'|'n'|'f'|'r'|'\"'|'\''|'\\');
fragment UnicodeEscape: 'u' HexDigit HexDigit HexDigit HexDigit;
fragment HexDigit: '0'..'9' | 'A'..'F' | 'a'..'f';
fragment Digit: '0'..'9';
fragment Bit: '0' | '1';
WS: (' ' | '\n' | '\t' | '\r') { SKIP(); };

