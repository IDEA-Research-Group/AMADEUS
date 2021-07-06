grammar Constraints;

// parser

expr:   left=expr op=('+'|'-') right=expr       #BinaryExpr
    |   NOT expr                                #NotExpr
    |   INT                                     #Integer
    |   '(' expr ')'                            #SubExpr
    ;

// lexer

INT :   [0-9]+ ;         // match integers
NOT :   'not' ;

WS  :   [ \t]+ -> skip ; // toss out whitespace