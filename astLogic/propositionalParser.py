# Generated from /home/german/AMADEUS/AmadeusEnv/bin/AMADEUS/astLogic/propositional.g4 by ANTLR 4.8
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO


def serializedATN():
    with StringIO() as buf:
        buf.write("\3\u608b\ua72a\u8133\ub9ed\u417c\u3be7\u7786\u5964\3\f")
        buf.write("\62\4\2\t\2\3\2\5\2\6\n\2\3\2\3\2\3\2\3\2\3\2\3\2\3\2")
        buf.write("\3\2\3\2\7\2\21\n\2\f\2\16\2\24\13\2\3\2\3\2\3\2\3\2\3")
        buf.write("\2\7\2\33\n\2\f\2\16\2\36\13\2\3\2\3\2\3\2\7\2#\n\2\f")
        buf.write("\2\16\2&\13\2\3\2\3\2\3\2\7\2+\n\2\f\2\16\2.\13\2\5\2")
        buf.write("\60\n\2\3\2\2\2\3\2\2\3\3\2\5\n\29\2/\3\2\2\2\4\6\7\n")
        buf.write("\2\2\5\4\3\2\2\2\5\6\3\2\2\2\6\7\3\2\2\2\7\b\7\3\2\2\b")
        buf.write("\t\5\2\2\2\t\n\7\4\2\2\n\60\3\2\2\2\13\f\7\3\2\2\f\r\5")
        buf.write("\2\2\2\r\22\7\4\2\2\16\17\t\2\2\2\17\21\5\2\2\2\20\16")
        buf.write("\3\2\2\2\21\24\3\2\2\2\22\20\3\2\2\2\22\23\3\2\2\2\23")
        buf.write("\60\3\2\2\2\24\22\3\2\2\2\25\26\7\3\2\2\26\27\5\2\2\2")
        buf.write("\27\34\7\4\2\2\30\31\t\2\2\2\31\33\7\13\2\2\32\30\3\2")
        buf.write("\2\2\33\36\3\2\2\2\34\32\3\2\2\2\34\35\3\2\2\2\35\60\3")
        buf.write("\2\2\2\36\34\3\2\2\2\37$\7\13\2\2 !\t\2\2\2!#\5\2\2\2")
        buf.write("\" \3\2\2\2#&\3\2\2\2$\"\3\2\2\2$%\3\2\2\2%\60\3\2\2\2")
        buf.write("&$\3\2\2\2\',\7\13\2\2()\t\2\2\2)+\7\13\2\2*(\3\2\2\2")
        buf.write("+.\3\2\2\2,*\3\2\2\2,-\3\2\2\2-\60\3\2\2\2.,\3\2\2\2/")
        buf.write("\5\3\2\2\2/\13\3\2\2\2/\25\3\2\2\2/\37\3\2\2\2/\'\3\2")
        buf.write("\2\2\60\3\3\2\2\2\b\5\22\34$,/")
        return buf.getvalue()


class propositionalParser ( Parser ):

    grammarFileName = "propositional.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'('", "')'", "'IMPLIES'", "'REQUIRES'", 
                     "'EXCLUDES'", "'AND'", "'OR'", "'NOT'" ]

    symbolicNames = [ "<INVALID>", "<INVALID>", "<INVALID>", "IMPLIES", 
                      "REQUIRES", "EXCLUDES", "AND", "OR", "NOT", "FEATURE", 
                      "WS" ]

    RULE_formula = 0

    ruleNames =  [ "formula" ]

    EOF = Token.EOF
    T__0=1
    T__1=2
    IMPLIES=3
    REQUIRES=4
    EXCLUDES=5
    AND=6
    OR=7
    NOT=8
    FEATURE=9
    WS=10

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.8")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class FormulaContext(ParserRuleContext):

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def formula(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(propositionalParser.FormulaContext)
            else:
                return self.getTypedRuleContext(propositionalParser.FormulaContext,i)


        def NOT(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.NOT)
            else:
                return self.getToken(propositionalParser.NOT, i)

        def IMPLIES(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.IMPLIES)
            else:
                return self.getToken(propositionalParser.IMPLIES, i)

        def REQUIRES(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.REQUIRES)
            else:
                return self.getToken(propositionalParser.REQUIRES, i)

        def EXCLUDES(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.EXCLUDES)
            else:
                return self.getToken(propositionalParser.EXCLUDES, i)

        def AND(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.AND)
            else:
                return self.getToken(propositionalParser.AND, i)

        def OR(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.OR)
            else:
                return self.getToken(propositionalParser.OR, i)

        def FEATURE(self, i:int=None):
            if i is None:
                return self.getTokens(propositionalParser.FEATURE)
            else:
                return self.getToken(propositionalParser.FEATURE, i)

        def getRuleIndex(self):
            return propositionalParser.RULE_formula

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterFormula" ):
                listener.enterFormula(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitFormula" ):
                listener.exitFormula(self)

        def accept(self, visitor:ParseTreeVisitor):
            if hasattr( visitor, "visitFormula" ):
                return visitor.visitFormula(self)
            else:
                return visitor.visitChildren(self)




    def formula(self):

        localctx = propositionalParser.FormulaContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_formula)
        self._la = 0 # Token type
        try:
            self.state = 45
            self._errHandler.sync(self)
            la_ = self._interp.adaptivePredict(self._input,5,self._ctx)
            if la_ == 1:
                self.enterOuterAlt(localctx, 1)
                self.state = 3
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==propositionalParser.NOT:
                    self.state = 2
                    self.match(propositionalParser.NOT)


                self.state = 5
                self.match(propositionalParser.T__0)
                self.state = 6
                self.formula()
                self.state = 7
                self.match(propositionalParser.T__1)
                pass

            elif la_ == 2:
                self.enterOuterAlt(localctx, 2)
                self.state = 9
                self.match(propositionalParser.T__0)
                self.state = 10
                self.formula()
                self.state = 11
                self.match(propositionalParser.T__1)
                self.state = 16
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,1,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 12
                        _la = self._input.LA(1)
                        if not((((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << propositionalParser.IMPLIES) | (1 << propositionalParser.REQUIRES) | (1 << propositionalParser.EXCLUDES) | (1 << propositionalParser.AND) | (1 << propositionalParser.OR) | (1 << propositionalParser.NOT))) != 0)):
                            self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 13
                        self.formula() 
                    self.state = 18
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,1,self._ctx)

                pass

            elif la_ == 3:
                self.enterOuterAlt(localctx, 3)
                self.state = 19
                self.match(propositionalParser.T__0)
                self.state = 20
                self.formula()
                self.state = 21
                self.match(propositionalParser.T__1)
                self.state = 26
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,2,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 22
                        _la = self._input.LA(1)
                        if not((((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << propositionalParser.IMPLIES) | (1 << propositionalParser.REQUIRES) | (1 << propositionalParser.EXCLUDES) | (1 << propositionalParser.AND) | (1 << propositionalParser.OR) | (1 << propositionalParser.NOT))) != 0)):
                            self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 23
                        self.match(propositionalParser.FEATURE) 
                    self.state = 28
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,2,self._ctx)

                pass

            elif la_ == 4:
                self.enterOuterAlt(localctx, 4)
                self.state = 29
                self.match(propositionalParser.FEATURE)
                self.state = 34
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,3,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 30
                        _la = self._input.LA(1)
                        if not((((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << propositionalParser.IMPLIES) | (1 << propositionalParser.REQUIRES) | (1 << propositionalParser.EXCLUDES) | (1 << propositionalParser.AND) | (1 << propositionalParser.OR) | (1 << propositionalParser.NOT))) != 0)):
                            self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 31
                        self.formula() 
                    self.state = 36
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,3,self._ctx)

                pass

            elif la_ == 5:
                self.enterOuterAlt(localctx, 5)
                self.state = 37
                self.match(propositionalParser.FEATURE)
                self.state = 42
                self._errHandler.sync(self)
                _alt = self._interp.adaptivePredict(self._input,4,self._ctx)
                while _alt!=2 and _alt!=ATN.INVALID_ALT_NUMBER:
                    if _alt==1:
                        self.state = 38
                        _la = self._input.LA(1)
                        if not((((_la) & ~0x3f) == 0 and ((1 << _la) & ((1 << propositionalParser.IMPLIES) | (1 << propositionalParser.REQUIRES) | (1 << propositionalParser.EXCLUDES) | (1 << propositionalParser.AND) | (1 << propositionalParser.OR) | (1 << propositionalParser.NOT))) != 0)):
                            self._errHandler.recoverInline(self)
                        else:
                            self._errHandler.reportMatch(self)
                            self.consume()
                        self.state = 39
                        self.match(propositionalParser.FEATURE) 
                    self.state = 44
                    self._errHandler.sync(self)
                    _alt = self._interp.adaptivePredict(self._input,4,self._ctx)

                pass


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





