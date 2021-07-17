grammar propositional;

formula
   : NOT ? '(' formula ')'
   | '(' formula ')' ((IMPLIES | REQUIRES | EXCLUDES | AND | OR | NOT) formula ) *
   | '(' formula ')' ((IMPLIES | REQUIRES | EXCLUDES | AND | OR | NOT) FEATURE ) *
   | FEATURE ((IMPLIES | REQUIRES | EXCLUDES | AND | OR | NOT) formula ) *
   | FEATURE ((IMPLIES | REQUIRES | EXCLUDES | AND | OR | NOT) FEATURE ) *
   ;

IMPLIES
   : 'IMPLIES'
   ;

REQUIRES
   : 'REQUIRES'
   ;

EXCLUDES
   : 'EXCLUDES'
   ;

AND
   : 'AND'
   ;

OR
   : 'OR'
   ;

NOT
   : 'NOT'
   ;

FEATURE
   : ('a' .. 'z' | 'A' .. 'Z' | '0' .. '9' | '_')
   ;


WS
   : [ \r\n\t] + -> channel (HIDDEN)
   ;