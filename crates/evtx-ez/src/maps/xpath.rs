//! XPath 1.0 over a rendered event, for map values.
//!
//! Maps used to run their XPaths against an XPathDocument of the event XML; [`NavDoc`] has the same nodes and values
//! that document had: no xmlns attributes, whitespace-only text dropped, line breaks in text as CRLF, white space in
//! attribute values as spaces. There are no namespaces, so names are matched as written.

use std::borrow::Cow;

use crate::binxml::render::OutElement;
use crate::output::xml::{Loaded, attribute_value, is_xmlns, loaded_children, xpath_text_value};

// ----- the document -----

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Root,
    Element,
    Attribute,
    Text,
    Pi,
}

struct NavNode<'a> {
    kind: Kind,
    name: &'a str,
    /// Text, attribute and processing instruction values
    value: Cow<'a, str>,
    parent: Option<u32>,
    /// Attribute nodes are right after their element: this range
    attributes: (u32, u32),
    children: Vec<u32>,
    /// The index in the parent's children (elements, text, PIs)
    index: u32,
}

/// A rendered event as an XPath data model; node ids are in document order
pub(crate) struct NavDoc<'a> {
    nodes: Vec<NavNode<'a>>,
}

impl<'a> NavDoc<'a> {
    pub fn new(root: &'a OutElement) -> NavDoc<'a> {
        let mut doc = NavDoc { nodes: Vec::with_capacity(64) };
        doc.nodes.push(NavNode {
            kind: Kind::Root,
            name: "",
            value: Cow::Borrowed(""),
            parent: None,
            attributes: (0, 0),
            children: Vec::new(),
            index: 0,
        });
        let id = doc.add_element(root, 0, 0);
        doc.nodes[0].children.push(id);
        doc
    }

    fn add_element(&mut self, e: &'a OutElement, parent: u32, index: u32) -> u32 {
        let id = self.nodes.len() as u32;
        self.nodes.push(NavNode {
            kind: Kind::Element,
            name: &e.name,
            value: Cow::Borrowed(""),
            parent: Some(parent),
            attributes: (0, 0),
            children: Vec::new(),
            index,
        });
        let first = self.nodes.len() as u32;
        for (k, v) in &e.attributes {
            if is_xmlns(k) {
                continue;
            }
            self.nodes.push(NavNode {
                kind: Kind::Attribute,
                name: k,
                value: attribute_value(v),
                parent: Some(id),
                attributes: (0, 0),
                children: Vec::new(),
                index: 0,
            });
        }
        self.nodes[id as usize].attributes = (first, self.nodes.len() as u32);

        let mut children = Vec::new();
        for c in loaded_children(e) {
            let index = children.len() as u32;
            let child = match c {
                Loaded::Element(ce) => self.add_element(ce, id, index),
                Loaded::Text(s) => {
                    let value = match s {
                        Cow::Borrowed(b) => xpath_text_value(b),
                        Cow::Owned(o) => Cow::Owned(xpath_text_value(&o).into_owned()),
                    };
                    self.leaf(Kind::Text, "", value, id, index)
                }
                Loaded::CData(s) => self.leaf(Kind::Text, "", Cow::Borrowed(s), id, index),
                Loaded::Pi { target, data } => self.leaf(Kind::Pi, target, Cow::Borrowed(data), id, index),
            };
            children.push(child);
        }
        self.nodes[id as usize].children = children;
        id
    }

    fn leaf(&mut self, kind: Kind, name: &'a str, value: Cow<'a, str>, parent: u32, index: u32) -> u32 {
        let id = self.nodes.len() as u32;
        self.nodes.push(NavNode { kind, name, value, parent: Some(parent), attributes: (0, 0), children: Vec::new(), index });
        id
    }

    fn node(&self, id: u32) -> &NavNode<'a> {
        &self.nodes[id as usize]
    }

    /// The XPath string-value: the value, or all descendant text
    fn string_value(&self, id: u32) -> Cow<'_, str> {
        let n = self.node(id);
        match n.kind {
            Kind::Text | Kind::Attribute | Kind::Pi => Cow::Borrowed(&n.value),
            Kind::Root | Kind::Element => {
                if n.children.len() == 1 && self.node(n.children[0]).kind == Kind::Text {
                    return Cow::Borrowed(&self.node(n.children[0]).value);
                }
                let mut s = String::new();
                self.append_text(id, &mut s);
                Cow::Owned(s)
            }
        }
    }

    fn append_text(&self, id: u32, s: &mut String) {
        for &c in &self.node(id).children {
            let n = self.node(c);
            match n.kind {
                Kind::Text => s.push_str(&n.value),
                Kind::Element => self.append_text(c, s),
                _ => {}
            }
        }
    }

    fn descendants(&self, id: u32, out: &mut Vec<u32>) {
        for &c in &self.node(id).children {
            out.push(c);
            self.descendants(c, out);
        }
    }

    /// The last node in `id`'s subtree (attributes included), for following/preceding
    fn subtree_end(&self, id: u32) -> u32 {
        let n = self.node(id);
        match n.children.last() {
            Some(&c) => self.subtree_end(c),
            None if n.attributes.1 > n.attributes.0 => n.attributes.1 - 1,
            None => id,
        }
    }
}

// ----- syntax -----

#[derive(Clone, Copy, Debug, PartialEq)]
enum Axis {
    Ancestor,
    AncestorOrSelf,
    Attribute,
    Child,
    Descendant,
    DescendantOrSelf,
    Following,
    FollowingSibling,
    Namespace,
    Parent,
    Preceding,
    PrecedingSibling,
    SelfAxis,
}

impl Axis {
    fn from_name(s: &str) -> Option<Axis> {
        Some(match s {
            "ancestor" => Axis::Ancestor,
            "ancestor-or-self" => Axis::AncestorOrSelf,
            "attribute" => Axis::Attribute,
            "child" => Axis::Child,
            "descendant" => Axis::Descendant,
            "descendant-or-self" => Axis::DescendantOrSelf,
            "following" => Axis::Following,
            "following-sibling" => Axis::FollowingSibling,
            "namespace" => Axis::Namespace,
            "parent" => Axis::Parent,
            "preceding" => Axis::Preceding,
            "preceding-sibling" => Axis::PrecedingSibling,
            "self" => Axis::SelfAxis,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
enum NodeTest {
    /// `*`: the axis's principal node type (attributes on the attribute axis, elements elsewhere)
    Any,
    Name(String),
    Text,
    Node,
    Comment,
    Pi(Option<String>),
}

#[derive(Clone, Debug)]
struct Step {
    axis: Axis,
    test: NodeTest,
    predicates: Vec<Expr>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Op {
    Or,
    And,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Func {
    Last,
    Position,
    Count,
    Id,
    LocalName,
    NamespaceUri,
    Name,
    String,
    Concat,
    StartsWith,
    Contains,
    SubstringBefore,
    SubstringAfter,
    Substring,
    StringLength,
    NormalizeSpace,
    Translate,
    Boolean,
    Not,
    True,
    False,
    Lang,
    Number,
    Sum,
    Floor,
    Ceiling,
    Round,
}

impl Func {
    /// The function and how many arguments it takes
    fn lookup(name: &str) -> Option<(Func, usize, usize)> {
        use Func::*;
        Some(match name {
            "last" => (Last, 0, 0),
            "position" => (Position, 0, 0),
            "count" => (Count, 1, 1),
            "id" => (Id, 1, 1),
            "local-name" => (LocalName, 0, 1),
            "namespace-uri" => (NamespaceUri, 0, 1),
            "name" => (Name, 0, 1),
            "string" => (String, 0, 1),
            "concat" => (Concat, 2, usize::MAX),
            "starts-with" => (StartsWith, 2, 2),
            "contains" => (Contains, 2, 2),
            "substring-before" => (SubstringBefore, 2, 2),
            "substring-after" => (SubstringAfter, 2, 2),
            "substring" => (Substring, 2, 3),
            "string-length" => (StringLength, 0, 1),
            "normalize-space" => (NormalizeSpace, 0, 1),
            "translate" => (Translate, 3, 3),
            "boolean" => (Boolean, 1, 1),
            "not" => (Not, 1, 1),
            "true" => (True, 0, 0),
            "false" => (False, 0, 0),
            "lang" => (Lang, 1, 1),
            "number" => (Number, 0, 1),
            "sum" => (Sum, 1, 1),
            "floor" => (Floor, 1, 1),
            "ceiling" => (Ceiling, 1, 1),
            "round" => (Round, 1, 1),
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
enum Expr {
    Binary(Op, Box<Expr>, Box<Expr>),
    Negate(Box<Expr>),
    Union(Box<Expr>, Box<Expr>),
    Literal(String),
    Number(f64),
    Call(Func, Vec<Expr>),
    /// A location path: from the root when absolute, else from the context node
    Path { absolute: bool, steps: Vec<Step> },
    /// A primary expression with predicates, then steps
    Filter { primary: Box<Expr>, predicates: Vec<Expr>, steps: Vec<Step> },
}

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    LParen,
    RParen,
    LBracket,
    RBracket,
    Dot,
    DotDot,
    At,
    Comma,
    ColonColon,
    Slash,
    DoubleSlash,
    Pipe,
    Plus,
    Minus,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Star,
    Dollar,
    Literal(String),
    Number(f64),
    /// An NCName, a QName, or `prefix:*`
    Name(String),
}

fn is_name_start(c: char) -> bool {
    c.is_alphabetic() || c == '_' || (c as u32) > 0x7F
}

fn is_name_char(c: char) -> bool {
    is_name_start(c) || c.is_ascii_digit() || c == '.' || c == '-' || c == '\u{B7}'
}

fn tokenize(s: &str) -> Result<Vec<Tok>, String> {
    let c: Vec<char> = s.chars().collect();
    let mut t = Vec::new();
    let mut i = 0;
    while i < c.len() {
        let ch = c[i];
        let next = c.get(i + 1).copied();
        let tok = match ch {
            ' ' | '\t' | '\r' | '\n' => {
                i += 1;
                continue;
            }
            '(' => Tok::LParen,
            ')' => Tok::RParen,
            '[' => Tok::LBracket,
            ']' => Tok::RBracket,
            '@' => Tok::At,
            ',' => Tok::Comma,
            '|' => Tok::Pipe,
            '+' => Tok::Plus,
            '-' => Tok::Minus,
            '=' => Tok::Eq,
            '*' => Tok::Star,
            '$' => Tok::Dollar,
            '!' if next == Some('=') => {
                i += 1;
                Tok::Ne
            }
            '<' if next == Some('=') => {
                i += 1;
                Tok::Le
            }
            '<' => Tok::Lt,
            '>' if next == Some('=') => {
                i += 1;
                Tok::Ge
            }
            '>' => Tok::Gt,
            ':' if next == Some(':') => {
                i += 1;
                Tok::ColonColon
            }
            '/' if next == Some('/') => {
                i += 1;
                Tok::DoubleSlash
            }
            '/' => Tok::Slash,
            '\'' | '"' => {
                let end = c[i + 1..].iter().position(|&x| x == ch).ok_or("This is an unclosed string.")?;
                let lit: String = c[i + 1..i + 1 + end].iter().collect();
                i += end + 2;
                t.push(Tok::Literal(lit));
                continue;
            }
            '.' if next == Some('.') => {
                i += 1;
                Tok::DotDot
            }
            '.' if !next.is_some_and(|n| n.is_ascii_digit()) => Tok::Dot,
            d if d.is_ascii_digit() || d == '.' => {
                let start = i;
                while i < c.len() && c[i].is_ascii_digit() {
                    i += 1;
                }
                if i < c.len() && c[i] == '.' {
                    i += 1;
                    while i < c.len() && c[i].is_ascii_digit() {
                        i += 1;
                    }
                }
                let text: String = c[start..i].iter().collect();
                t.push(Tok::Number(text.parse().map_err(|_| format!("'{text}' is not a number."))?));
                continue;
            }
            n if is_name_start(n) => {
                let start = i;
                while i < c.len() && is_name_char(c[i]) {
                    i += 1;
                }
                // a prefix (not an axis' ::)
                if i + 1 < c.len() && c[i] == ':' && c[i + 1] != ':' {
                    if c[i + 1] == '*' {
                        i += 2;
                    } else if is_name_start(c[i + 1]) {
                        i += 1;
                        while i < c.len() && is_name_char(c[i]) {
                            i += 1;
                        }
                    }
                }
                t.push(Tok::Name(c[start..i].iter().collect()));
                continue;
            }
            other => return Err(format!("'{other}' is not a valid XPath character.")),
        };
        t.push(tok);
        i += 1;
    }
    Ok(t)
}

struct Parser {
    t: Vec<Tok>,
    i: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }

    fn peek_at(&self, n: usize) -> Option<&Tok> {
        self.t.get(self.i + n)
    }

    fn eat(&mut self, tok: &Tok) -> bool {
        if self.peek() == Some(tok) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn expect(&mut self, tok: &Tok) -> Result<(), String> {
        if self.eat(tok) { Ok(()) } else { Err(format!("Expected {tok:?}.")) }
    }

    fn is_op_name(&self, name: &str) -> bool {
        matches!(self.peek(), Some(Tok::Name(n)) if n == name)
    }

    fn expr(&mut self) -> Result<Expr, String> {
        self.or()
    }

    fn or(&mut self) -> Result<Expr, String> {
        let mut e = self.and()?;
        while self.is_op_name("or") {
            self.i += 1;
            e = Expr::Binary(Op::Or, Box::new(e), Box::new(self.and()?));
        }
        Ok(e)
    }

    fn and(&mut self) -> Result<Expr, String> {
        let mut e = self.equality()?;
        while self.is_op_name("and") {
            self.i += 1;
            e = Expr::Binary(Op::And, Box::new(e), Box::new(self.equality()?));
        }
        Ok(e)
    }

    fn equality(&mut self) -> Result<Expr, String> {
        let mut e = self.relational()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Eq) => Op::Eq,
                Some(Tok::Ne) => Op::Ne,
                _ => return Ok(e),
            };
            self.i += 1;
            e = Expr::Binary(op, Box::new(e), Box::new(self.relational()?));
        }
    }

    fn relational(&mut self) -> Result<Expr, String> {
        let mut e = self.additive()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Lt) => Op::Lt,
                Some(Tok::Le) => Op::Le,
                Some(Tok::Gt) => Op::Gt,
                Some(Tok::Ge) => Op::Ge,
                _ => return Ok(e),
            };
            self.i += 1;
            e = Expr::Binary(op, Box::new(e), Box::new(self.additive()?));
        }
    }

    fn additive(&mut self) -> Result<Expr, String> {
        let mut e = self.multiplicative()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => Op::Add,
                Some(Tok::Minus) => Op::Sub,
                _ => return Ok(e),
            };
            self.i += 1;
            e = Expr::Binary(op, Box::new(e), Box::new(self.multiplicative()?));
        }
    }

    fn multiplicative(&mut self) -> Result<Expr, String> {
        let mut e = self.unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => Op::Mul,
                Some(Tok::Name(n)) if n == "div" => Op::Div,
                Some(Tok::Name(n)) if n == "mod" => Op::Mod,
                _ => return Ok(e),
            };
            self.i += 1;
            e = Expr::Binary(op, Box::new(e), Box::new(self.unary()?));
        }
    }

    fn unary(&mut self) -> Result<Expr, String> {
        if self.eat(&Tok::Minus) {
            return Ok(Expr::Negate(Box::new(self.unary()?)));
        }
        self.union()
    }

    fn union(&mut self) -> Result<Expr, String> {
        let mut e = self.path()?;
        while self.eat(&Tok::Pipe) {
            e = Expr::Union(Box::new(e), Box::new(self.path()?));
        }
        Ok(e)
    }

    fn starts_primary(&self) -> bool {
        match self.peek() {
            Some(Tok::Literal(_) | Tok::Number(_) | Tok::LParen | Tok::Dollar) => true,
            Some(Tok::Name(n)) => {
                self.peek_at(1) == Some(&Tok::LParen)
                    && !matches!(n.as_str(), "node" | "text" | "comment" | "processing-instruction")
            }
            _ => false,
        }
    }

    fn path(&mut self) -> Result<Expr, String> {
        if self.starts_primary() {
            let primary = self.primary()?;
            let mut predicates = Vec::new();
            while self.peek() == Some(&Tok::LBracket) {
                predicates.push(self.predicate()?);
            }
            let mut steps = Vec::new();
            if matches!(self.peek(), Some(Tok::Slash | Tok::DoubleSlash)) {
                self.relative_steps(&mut steps, true)?;
            }
            if predicates.is_empty() && steps.is_empty() {
                return Ok(primary);
            }
            return Ok(Expr::Filter { primary: Box::new(primary), predicates, steps });
        }

        let mut steps = Vec::new();
        match self.peek() {
            Some(Tok::Slash) => {
                self.i += 1;
                if self.starts_step() {
                    self.relative_steps(&mut steps, false)?;
                }
                Ok(Expr::Path { absolute: true, steps })
            }
            Some(Tok::DoubleSlash) => {
                self.relative_steps(&mut steps, true)?;
                Ok(Expr::Path { absolute: true, steps })
            }
            _ => {
                self.relative_steps(&mut steps, false)?;
                Ok(Expr::Path { absolute: false, steps })
            }
        }
    }

    fn starts_step(&self) -> bool {
        matches!(self.peek(), Some(Tok::Dot | Tok::DotDot | Tok::At | Tok::Star | Tok::Name(_)))
    }

    /// Steps, starting with a separator when `leading` (`/` or `//`)
    fn relative_steps(&mut self, steps: &mut Vec<Step>, leading: bool) -> Result<(), String> {
        let mut need_separator = leading;
        loop {
            if need_separator {
                match self.peek() {
                    Some(Tok::Slash) => self.i += 1,
                    Some(Tok::DoubleSlash) => {
                        self.i += 1;
                        steps.push(Step { axis: Axis::DescendantOrSelf, test: NodeTest::Node, predicates: Vec::new() });
                    }
                    _ => return Ok(()),
                }
            }
            steps.push(self.step()?);
            need_separator = true;
        }
    }

    fn step(&mut self) -> Result<Step, String> {
        if self.eat(&Tok::Dot) {
            return Ok(Step { axis: Axis::SelfAxis, test: NodeTest::Node, predicates: Vec::new() });
        }
        if self.eat(&Tok::DotDot) {
            return Ok(Step { axis: Axis::Parent, test: NodeTest::Node, predicates: Vec::new() });
        }
        let mut axis = Axis::Child;
        if self.eat(&Tok::At) {
            axis = Axis::Attribute;
        } else if let (Some(Tok::Name(n)), Some(Tok::ColonColon)) = (self.peek(), self.peek_at(1)) {
            axis = Axis::from_name(n).ok_or_else(|| format!("'{n}' is not a valid axis."))?;
            self.i += 2;
        }

        let test = match self.peek().cloned() {
            Some(Tok::Star) => {
                self.i += 1;
                NodeTest::Any
            }
            Some(Tok::Name(n)) => {
                self.i += 1;
                if self.peek() == Some(&Tok::LParen) {
                    self.i += 1;
                    let test = match n.as_str() {
                        "node" => NodeTest::Node,
                        "text" => NodeTest::Text,
                        "comment" => NodeTest::Comment,
                        "processing-instruction" => match self.peek().cloned() {
                            Some(Tok::Literal(l)) => {
                                self.i += 1;
                                NodeTest::Pi(Some(l))
                            }
                            _ => NodeTest::Pi(None),
                        },
                        _ => return Err(format!("'{n}()' is not a node test.")),
                    };
                    self.expect(&Tok::RParen)?;
                    test
                } else if n.contains(':') {
                    // there is no namespace manager to resolve a prefix with
                    return Err("Namespace Manager or XsltContext needed. This query has a prefix, variable, or user-defined function.".into());
                } else {
                    NodeTest::Name(n)
                }
            }
            _ => return Err("Expression must evaluate to a node-set.".into()),
        };

        let mut predicates = Vec::new();
        while self.peek() == Some(&Tok::LBracket) {
            predicates.push(self.predicate()?);
        }
        Ok(Step { axis, test, predicates })
    }

    fn predicate(&mut self) -> Result<Expr, String> {
        self.expect(&Tok::LBracket)?;
        let e = self.expr()?;
        self.expect(&Tok::RBracket)?;
        Ok(e)
    }

    fn primary(&mut self) -> Result<Expr, String> {
        match self.peek().cloned() {
            Some(Tok::Literal(l)) => {
                self.i += 1;
                Ok(Expr::Literal(l))
            }
            Some(Tok::Number(n)) => {
                self.i += 1;
                Ok(Expr::Number(n))
            }
            Some(Tok::LParen) => {
                self.i += 1;
                let e = self.expr()?;
                self.expect(&Tok::RParen)?;
                Ok(e)
            }
            Some(Tok::Dollar) => {
                Err("Namespace Manager or XsltContext needed. This query has a prefix, variable, or user-defined function.".into())
            }
            Some(Tok::Name(n)) => {
                self.i += 2;
                let (func, min, max) = Func::lookup(&n).ok_or_else(|| {
                    "Namespace Manager or XsltContext needed. This query has a prefix, variable, or user-defined function."
                        .to_string()
                })?;
                let mut args = Vec::new();
                if !self.eat(&Tok::RParen) {
                    loop {
                        args.push(self.expr()?);
                        if self.eat(&Tok::RParen) {
                            break;
                        }
                        self.expect(&Tok::Comma)?;
                    }
                }
                if args.len() < min || args.len() > max {
                    return Err(format!("Function '{n}()' in '' has an invalid number of arguments."));
                }
                Ok(Expr::Call(func, args))
            }
            _ => Err("Expression must evaluate to a node-set.".into()),
        }
    }
}

// ----- evaluation -----

enum Val {
    Nodes(Vec<u32>),
    Num(f64),
    Str(String),
    Bool(bool),
}

#[derive(Clone, Copy)]
struct Ctx {
    node: u32,
    position: usize,
    size: usize,
}

/// A compiled XPath expression
#[derive(Clone, Debug)]
pub struct XPath {
    expr: Expr,
}

impl XPath {
    /// Compiles an expression; the error is the message .NET gives (roughly)
    pub fn compile(s: &str) -> Result<XPath, String> {
        let t = tokenize(s)?;
        if t.is_empty() {
            return Err("Expression must evaluate to a node-set.".into());
        }
        let mut p = Parser { t, i: 0 };
        let expr = p.expr()?;
        if p.i != p.t.len() {
            return Err(format!("'{s}' has an invalid token."));
        }
        Ok(XPath { expr })
    }

    /// A map value: the first node a path selects, or what an expression evaluates to (issue #99), e.g.
    /// `round(/Event/EventData/Data[@Name="RemainingCapacity"] div /Event/EventData/Data[@Name="FullChargeCapacity"] * 100)`.
    /// None when nothing is selected, or a number can't be calculated (a value is missing or not a number).
    pub(crate) fn map_value(&self, doc: &NavDoc) -> Option<String> {
        let ctx = Ctx { node: 0, position: 1, size: 1 };
        match eval(doc, &self.expr, ctx) {
            Val::Nodes(n) => n.first().map(|&id| doc.string_value(id).into_owned()),
            Val::Num(d) => {
                if d.is_nan() || d.is_infinite() {
                    None
                } else if d == 0.0 {
                    // not "-0"
                    Some("0".into())
                } else if d.floor() == d && d.abs() < 1e15 {
                    Some(format!("{d:.0}"))
                } else {
                    Some(fixed_15(d))
                }
            }
            Val::Bool(b) => Some(if b { "true" } else { "false" }.into()),
            Val::Str(s) => Some(s),
        }
    }
}

/// .NET's `0.###############`: the number to 15 significant digits, then at most 15 decimals, no exponent
fn fixed_15(d: f64) -> String {
    let sci = format!("{:.14e}", d.abs());
    let (mantissa, exp) = sci.split_once('e').unwrap();
    let mut exp: i32 = exp.parse().unwrap();
    let mut digits: Vec<u8> = mantissa.bytes().filter(u8::is_ascii_digit).map(|c| c - b'0').collect();
    // digits[i] is at 10^(exp - i); decimal place i - exp. Keep those at place 15 or above, rounding half up.
    let keep = (16 + exp).clamp(0, digits.len() as i32) as usize;
    if keep < digits.len() {
        let round_up = digits[keep] >= 5;
        digits.truncate(keep);
        if round_up {
            let mut i = digits.len();
            loop {
                if i == 0 {
                    digits.insert(0, 1);
                    exp += 1;
                    break;
                }
                i -= 1;
                if digits[i] == 9 {
                    digits[i] = 0;
                } else {
                    digits[i] += 1;
                    break;
                }
            }
        }
    }
    let mut int_part = String::new();
    let mut frac_part = String::new();
    for (i, &digit) in digits.iter().enumerate() {
        let place = i as i32 - exp;
        if place <= 0 {
            int_part.push((b'0' + digit) as char);
        } else {
            while (frac_part.len() as i32) < place - 1 {
                frac_part.push('0');
            }
            frac_part.push((b'0' + digit) as char);
        }
    }
    let whole_digits = exp + 1;
    while (int_part.len() as i32) < whole_digits {
        int_part.push('0');
    }
    if int_part.is_empty() {
        int_part.push('0');
    }
    let frac = frac_part.trim_end_matches('0');
    let mut s = String::new();
    if d < 0.0 && (int_part != "0" || !frac.is_empty()) {
        s.push('-');
    }
    s.push_str(&int_part);
    if !frac.is_empty() {
        s.push('.');
        s.push_str(frac);
    }
    s
}

fn eval(doc: &NavDoc, e: &Expr, ctx: Ctx) -> Val {
    match e {
        Expr::Literal(s) => Val::Str(s.clone()),
        Expr::Number(n) => Val::Num(*n),
        Expr::Negate(a) => Val::Num(-number(doc, &eval(doc, a, ctx))),
        Expr::Union(a, b) => {
            let mut nodes = nodes_of(eval(doc, a, ctx));
            nodes.extend(nodes_of(eval(doc, b, ctx)));
            nodes.sort_unstable();
            nodes.dedup();
            Val::Nodes(nodes)
        }
        Expr::Binary(op, a, b) => binary(doc, *op, a, b, ctx),
        Expr::Call(f, args) => call(doc, *f, args, ctx),
        Expr::Path { absolute, steps } => {
            let start = if *absolute { 0 } else { ctx.node };
            Val::Nodes(apply_steps(doc, vec![start], steps))
        }
        Expr::Filter { primary, predicates, steps } => {
            let v = eval(doc, primary, ctx);
            if predicates.is_empty() && steps.is_empty() {
                return v;
            }
            let mut nodes = nodes_of(v);
            for p in predicates {
                nodes = filter(doc, nodes, p);
            }
            Val::Nodes(apply_steps(doc, nodes, steps))
        }
    }
}

fn nodes_of(v: Val) -> Vec<u32> {
    match v {
        Val::Nodes(n) => n,
        // a value that is not a node-set where one is needed selects nothing
        _ => Vec::new(),
    }
}

fn apply_steps(doc: &NavDoc, mut current: Vec<u32>, steps: &[Step]) -> Vec<u32> {
    for step in steps {
        let mut next = Vec::new();
        for &n in &current {
            let mut selected: Vec<u32> = axis_nodes(doc, n, step.axis).into_iter().filter(|&id| matches(doc, id, step)).collect();
            for p in &step.predicates {
                selected = filter(doc, selected, p);
            }
            next.extend(selected);
        }
        next.sort_unstable();
        next.dedup();
        current = next;
    }
    current
}

/// Keeps the nodes the predicate is true for; positions are in the order given (axis order)
fn filter(doc: &NavDoc, nodes: Vec<u32>, p: &Expr) -> Vec<u32> {
    let size = nodes.len();
    nodes
        .into_iter()
        .enumerate()
        .filter(|&(i, id)| {
            let ctx = Ctx { node: id, position: i + 1, size };
            match eval(doc, p, ctx) {
                Val::Num(n) => n == (i + 1) as f64,
                v => boolean(&v),
            }
        })
        .map(|(_, id)| id)
        .collect()
}

/// The nodes on an axis, in axis order (reverse document order for reverse axes)
fn axis_nodes(doc: &NavDoc, id: u32, axis: Axis) -> Vec<u32> {
    let n = doc.node(id);
    let mut out = Vec::new();
    match axis {
        Axis::Child => out.extend(&n.children),
        Axis::Attribute => out.extend(n.attributes.0..n.attributes.1),
        Axis::SelfAxis => out.push(id),
        Axis::Parent => out.extend(n.parent),
        Axis::Descendant => doc.descendants(id, &mut out),
        Axis::DescendantOrSelf => {
            out.push(id);
            doc.descendants(id, &mut out);
        }
        Axis::Ancestor | Axis::AncestorOrSelf => {
            if axis == Axis::AncestorOrSelf {
                out.push(id);
            }
            let mut p = n.parent;
            while let Some(pid) = p {
                out.push(pid);
                p = doc.node(pid).parent;
            }
        }
        Axis::FollowingSibling | Axis::PrecedingSibling => {
            if n.kind == Kind::Attribute {
                return out;
            }
            if let Some(pid) = n.parent {
                let siblings = &doc.node(pid).children;
                let i = n.index as usize;
                if axis == Axis::FollowingSibling {
                    out.extend(&siblings[i + 1..]);
                } else {
                    out.extend(siblings[..i].iter().rev());
                }
            }
        }
        Axis::Following => {
            // everything after the node's subtree, except attributes
            let start = if n.kind == Kind::Attribute { n.parent.unwrap() } else { id };
            let after = doc.subtree_end(start) + 1;
            out.extend((after..doc.nodes.len() as u32).filter(|&x| doc.node(x).kind != Kind::Attribute));
        }
        Axis::Preceding => {
            // everything before the node, except ancestors and attributes
            let start = if n.kind == Kind::Attribute { n.parent.unwrap() } else { id };
            let mut ancestors = Vec::new();
            let mut p = doc.node(start).parent;
            while let Some(pid) = p {
                ancestors.push(pid);
                p = doc.node(pid).parent;
            }
            out.extend((0..start).rev().filter(|x| doc.node(*x).kind != Kind::Attribute && !ancestors.contains(x)));
        }
        Axis::Namespace => {}
    }
    out
}

fn matches(doc: &NavDoc, id: u32, step: &Step) -> bool {
    let n = doc.node(id);
    let principal = if step.axis == Axis::Attribute { Kind::Attribute } else { Kind::Element };
    match &step.test {
        NodeTest::Node => true,
        NodeTest::Any => n.kind == principal,
        NodeTest::Name(name) => n.kind == principal && n.name == name,
        NodeTest::Text => n.kind == Kind::Text,
        NodeTest::Comment => false,
        NodeTest::Pi(target) => n.kind == Kind::Pi && target.as_ref().is_none_or(|t| t == n.name),
    }
}

fn binary(doc: &NavDoc, op: Op, a: &Expr, b: &Expr, ctx: Ctx) -> Val {
    match op {
        Op::Or => Val::Bool(boolean(&eval(doc, a, ctx)) || boolean(&eval(doc, b, ctx))),
        Op::And => Val::Bool(boolean(&eval(doc, a, ctx)) && boolean(&eval(doc, b, ctx))),
        Op::Add | Op::Sub | Op::Mul | Op::Div | Op::Mod => {
            let x = number(doc, &eval(doc, a, ctx));
            let y = number(doc, &eval(doc, b, ctx));
            Val::Num(match op {
                Op::Add => x + y,
                Op::Sub => x - y,
                Op::Mul => x * y,
                Op::Div => x / y,
                _ => x % y,
            })
        }
        _ => {
            let x = eval(doc, a, ctx);
            let y = eval(doc, b, ctx);
            Val::Bool(compare(doc, op, &x, &y))
        }
    }
}

/// XPath 1.0 comparisons (3.4), node-sets compared by any of their nodes' string-values
fn compare(doc: &NavDoc, op: Op, x: &Val, y: &Val) -> bool {
    match (x, y) {
        (Val::Nodes(_), Val::Bool(_)) | (Val::Bool(_), Val::Nodes(_)) => {
            compare_atoms(op, &Val::Bool(boolean(x)), &Val::Bool(boolean(y)))
        }
        (Val::Nodes(a), Val::Nodes(b)) => {
            let bs: Vec<_> = b.iter().map(|&n| doc.string_value(n)).collect();
            a.iter().any(|&n| {
                let s = doc.string_value(n);
                bs.iter().any(|t| compare_atoms(op, &Val::Str(s.to_string()), &Val::Str(t.to_string())))
            })
        }
        (Val::Nodes(a), other) => a.iter().any(|&n| node_vs(doc, op, n, other, false)),
        (other, Val::Nodes(b)) => b.iter().any(|&n| node_vs(doc, op, n, other, true)),
        _ => compare_atoms(op, x, y),
    }
}

fn node_vs(doc: &NavDoc, op: Op, n: u32, other: &Val, swapped: bool) -> bool {
    let s = doc.string_value(n).into_owned();
    let v = match other {
        Val::Num(_) => Val::Num(str_to_number(&s)),
        _ => Val::Str(s),
    };
    if swapped { compare_atoms(op, other, &v) } else { compare_atoms(op, &v, other) }
}

fn compare_atoms(op: Op, x: &Val, y: &Val) -> bool {
    let num = |v: &Val| match v {
        Val::Num(n) => *n,
        Val::Str(s) => str_to_number(s),
        Val::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Val::Nodes(_) => f64::NAN,
    };
    match op {
        Op::Eq | Op::Ne => {
            let eq = match (x, y) {
                (Val::Bool(_), _) | (_, Val::Bool(_)) => boolean(x) == boolean(y),
                (Val::Num(_), _) | (_, Val::Num(_)) => num(x) == num(y),
                (Val::Str(a), Val::Str(b)) => a == b,
                _ => false,
            };
            if op == Op::Eq { eq } else { !eq }
        }
        Op::Lt => num(x) < num(y),
        Op::Le => num(x) <= num(y),
        Op::Gt => num(x) > num(y),
        Op::Ge => num(x) >= num(y),
        _ => false,
    }
}

fn boolean(v: &Val) -> bool {
    match v {
        Val::Bool(b) => *b,
        Val::Num(n) => *n != 0.0 && !n.is_nan(),
        Val::Str(s) => !s.is_empty(),
        Val::Nodes(n) => !n.is_empty(),
    }
}

fn number(doc: &NavDoc, v: &Val) -> f64 {
    match v {
        Val::Num(n) => *n,
        Val::Bool(b) => {
            if *b {
                1.0
            } else {
                0.0
            }
        }
        Val::Str(s) => str_to_number(s),
        Val::Nodes(n) => n.first().map(|&id| str_to_number(&doc.string_value(id))).unwrap_or(f64::NAN),
    }
}

fn string(doc: &NavDoc, v: &Val) -> String {
    match v {
        Val::Str(s) => s.clone(),
        Val::Bool(b) => if *b { "true" } else { "false" }.into(),
        Val::Num(n) => number_to_string(*n),
        Val::Nodes(n) => n.first().map(|&id| doc.string_value(id).into_owned()).unwrap_or_default(),
    }
}

/// XPath's number(): optional white space, an optional minus, digits with an optional decimal point
fn str_to_number(s: &str) -> f64 {
    let t = s.trim_matches(|c| matches!(c, ' ' | '\t' | '\r' | '\n'));
    let body = t.strip_prefix('-').unwrap_or(t);
    let valid = !body.is_empty()
        && body != "."
        && body.chars().all(|c| c.is_ascii_digit() || c == '.')
        && body.chars().filter(|&c| c == '.').count() <= 1;
    if valid { t.parse().unwrap_or(f64::NAN) } else { f64::NAN }
}

/// XPath's string() of a number: no exponent, no decimal point for integers
fn number_to_string(n: f64) -> String {
    if n.is_nan() {
        return "NaN".into();
    }
    if n.is_infinite() {
        return if n > 0.0 { "Infinity".into() } else { "-Infinity".into() };
    }
    if n == 0.0 {
        return "0".into();
    }
    if n.fract() == 0.0 && n.abs() < 1e15 {
        return format!("{n:.0}");
    }
    // shortest round-trip digits, written out without an exponent
    let s = format!("{n}");
    if !s.contains('e') {
        return s;
    }
    fixed_15(n)
}

fn call(doc: &NavDoc, f: Func, args: &[Expr], ctx: Ctx) -> Val {
    let arg = |i: usize| eval(doc, &args[i], ctx);
    let arg_string = |i: usize| -> String {
        if args.len() > i { string(doc, &arg(i)) } else { doc.string_value(ctx.node).into_owned() }
    };
    let first_node = |i: usize| -> Option<u32> {
        if args.len() > i {
            nodes_of(arg(i)).first().copied()
        } else {
            Some(ctx.node)
        }
    };
    match f {
        Func::Last => Val::Num(ctx.size as f64),
        Func::Position => Val::Num(ctx.position as f64),
        Func::Count => Val::Num(nodes_of(arg(0)).len() as f64),
        Func::Id => Val::Nodes(Vec::new()),
        Func::LocalName | Func::Name => Val::Str(first_node(0).map(|id| doc.node(id).name.to_string()).unwrap_or_default()),
        Func::NamespaceUri => Val::Str(String::new()),
        Func::String => Val::Str(arg_string(0)),
        Func::Concat => Val::Str((0..args.len()).map(|i| string(doc, &arg(i))).collect()),
        Func::StartsWith => Val::Bool(string(doc, &arg(0)).starts_with(&string(doc, &arg(1)))),
        Func::Contains => Val::Bool(string(doc, &arg(0)).contains(&string(doc, &arg(1)))),
        Func::SubstringBefore => {
            let (s, t) = (string(doc, &arg(0)), string(doc, &arg(1)));
            Val::Str(s.find(&t).map(|i| s[..i].to_string()).unwrap_or_default())
        }
        Func::SubstringAfter => {
            let (s, t) = (string(doc, &arg(0)), string(doc, &arg(1)));
            Val::Str(s.find(&t).map(|i| s[i + t.len()..].to_string()).unwrap_or_default())
        }
        Func::Substring => {
            let s: Vec<char> = string(doc, &arg(0)).chars().collect();
            let start = round(number(doc, &arg(1)));
            let end = if args.len() > 2 { start + round(number(doc, &arg(2))) } else { f64::INFINITY };
            Val::Str(
                s.iter()
                    .enumerate()
                    .filter(|(i, _)| {
                        let p = (*i + 1) as f64;
                        p >= start && p < end
                    })
                    .map(|(_, c)| c)
                    .collect(),
            )
        }
        Func::StringLength => Val::Num(arg_string(0).chars().count() as f64),
        Func::NormalizeSpace => {
            Val::Str(arg_string(0).split(|c| matches!(c, ' ' | '\t' | '\r' | '\n')).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" "))
        }
        Func::Translate => {
            let s = string(doc, &arg(0));
            let from: Vec<char> = string(doc, &arg(1)).chars().collect();
            let to: Vec<char> = string(doc, &arg(2)).chars().collect();
            Val::Str(
                s.chars()
                    .filter_map(|c| match from.iter().position(|&x| x == c) {
                        Some(i) => to.get(i).copied(),
                        None => Some(c),
                    })
                    .collect(),
            )
        }
        Func::Boolean => Val::Bool(boolean(&arg(0))),
        Func::Not => Val::Bool(!boolean(&arg(0))),
        Func::True => Val::Bool(true),
        Func::False => Val::Bool(false),
        Func::Lang => Val::Bool(false),
        Func::Number => {
            if args.is_empty() {
                Val::Num(str_to_number(&doc.string_value(ctx.node)))
            } else {
                Val::Num(number(doc, &arg(0)))
            }
        }
        Func::Sum => Val::Num(nodes_of(arg(0)).iter().map(|&id| str_to_number(&doc.string_value(id))).sum()),
        Func::Floor => Val::Num(number(doc, &arg(0)).floor()),
        Func::Ceiling => Val::Num(number(doc, &arg(0)).ceil()),
        Func::Round => Val::Num(round(number(doc, &arg(0)))),
    }
}

/// XPath's round(): the closest integer, .5 up
fn round(n: f64) -> f64 {
    if n.is_nan() || n.is_infinite() {
        return n;
    }
    let r = (n + 0.5).floor();
    if r == 0.0 && n < 0.0 { -0.0 } else { r }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::binxml::render::OutNode;

    fn el(name: &str, attrs: &[(&str, &str)], children: Vec<OutNode>) -> OutElement {
        OutElement {
            name: name.into(),
            attributes: attrs.iter().map(|(k, v)| ((*k).into(), (*v).to_string())).collect(),
            children,
            empty_tag: false,
        }
    }

    fn text(s: &str) -> OutNode {
        OutNode::Text(s.into())
    }

    fn event() -> OutElement {
        el(
            "Event",
            &[("xmlns", "http://schemas.microsoft.com/win/2004/08/events/event")],
            vec![
                OutNode::Element(el(
                    "System",
                    &[],
                    vec![
                        OutNode::Element(el("EventID", &[], vec![text("4624")])),
                        OutNode::Element(el("Correlation", &[("ActivityID", "{ABC}")], vec![])),
                        OutNode::Element(el("Computer", &[], vec![text("host1")])),
                    ],
                )),
                OutNode::Element(el(
                    "EventData",
                    &[],
                    vec![
                        OutNode::Element(el("Data", &[("Name", "TargetUserName")], vec![text("bob")])),
                        OutNode::Element(el("Data", &[("Name", "LogonType")], vec![text("3")])),
                        OutNode::Element(el("Data", &[("Name", "Full")], vec![text("200")])),
                        OutNode::Element(el("Data", &[("Name", "Remaining")], vec![text("50")])),
                        OutNode::Element(el("Data", &[("Name", "Multi")], vec![text("a\nb")])),
                        OutNode::Element(el("Data", &[("Name", "Empty")], vec![text("  ")])),
                    ],
                )),
            ],
        )
    }

    fn value(xpath: &str) -> Option<String> {
        let e = event();
        let doc = NavDoc::new(&e);
        XPath::compile(xpath).unwrap().map_value(&doc)
    }

    #[test]
    fn paths() {
        assert_eq!(value("/Event/EventData/Data[@Name=\"TargetUserName\"]").as_deref(), Some("bob"));
        assert_eq!(value("/Event/EventData/Data[@Name='LogonType']").as_deref(), Some("3"));
        assert_eq!(value("/Event/EventData/Data").as_deref(), Some("bob"));
        assert_eq!(value("/Event/EventData/Data[2]").as_deref(), Some("3"));
        assert_eq!(value("/Event/EventData/Data[last()]").as_deref(), Some(""));
        assert_eq!(value("/Event/System/Correlation/@ActivityID").as_deref(), Some("{ABC}"));
        assert_eq!(value("/Event/System/Computer/text()").as_deref(), Some("host1"));
        assert_eq!(value("//Computer").as_deref(), Some("host1"));
        assert_eq!(value("/Event/EventData/Data[@Name=\"Missing\"]"), None);
        assert_eq!(value("/Event/@xmlns"), None);
        // line breaks in text are CRLF, as an XPathDocument of the written XML had them
        assert_eq!(value("/Event/EventData/Data[@Name='Multi']").as_deref(), Some("a\r\nb"));
        assert_eq!(value("/Event/EventData/Data[@Name='Empty']").as_deref(), Some(""));
        assert_eq!(value("/Event/EventData/Data[@Name='LogonType']/preceding-sibling::Data[1]/@Name").as_deref(), Some("TargetUserName"));
        assert_eq!(value("/Event/System/EventID/following::Data[1]").as_deref(), Some("bob"));
        assert_eq!(value("/Event/EventData/Data[3]/ancestor::*[1]/@Name"), None);
        assert_eq!(value("name(/Event/EventData/Data[3]/..)").as_deref(), Some("EventData"));
    }

    #[test]
    fn expressions() {
        assert_eq!(
            value("round(/Event/EventData/Data[@Name=\"Remaining\"] div /Event/EventData/Data[@Name=\"Full\"] * 100)").as_deref(),
            Some("25")
        );
        assert_eq!(value("/Event/EventData/Data[@Name='Remaining'] div 3").as_deref(), Some("16.6666666666667"));
        assert_eq!(value("/Event/EventData/Data[@Name='Nope'] * 2"), None);
        assert_eq!(value("1 div 0"), None);
        assert_eq!(value("-0"), Some("0".into()));
        assert_eq!(value("count(/Event/EventData/Data)").as_deref(), Some("6"));
        assert_eq!(value("concat(/Event/System/Computer, ':', 1.5)").as_deref(), Some("host1:1.5"));
        assert_eq!(value("/Event/System/EventID = 4624").as_deref(), Some("true"));
        assert_eq!(value("/Event/System/EventID > 5000 or false()").as_deref(), Some("false"));
        assert_eq!(value("substring('12345', 1.5, 2.6)").as_deref(), Some("234"));
        assert_eq!(value("translate('bar','abc','ABC')").as_deref(), Some("BAr"));
        assert_eq!(value("normalize-space('  a   b ')").as_deref(), Some("a b"));
        assert_eq!(value("/Event/EventData/Data[@Name='Nope'] = false()").as_deref(), Some("true"));
        assert_eq!(value("string(/Event/EventData/Data[@Name='Full'] * 1.5)").as_deref(), Some("300"));
    }

    #[test]
    fn compile_errors() {
        assert!(XPath::compile("").is_err());
        assert!(XPath::compile("/Event/EventData/Data[@Name=\"x\"").is_err());
        assert!(XPath::compile("/Event/foo:Data").is_err());
        assert!(XPath::compile("unknown-function(1)").is_err());
        assert!(XPath::compile("'unclosed").is_err());
        assert!(XPath::compile("/Event/EventData/Data[@Name=\"x\"]]").is_err());
    }

    #[test]
    fn fifteen_digits() {
        assert_eq!(fixed_15(16.666666666666668), "16.6666666666667");
        assert_eq!(fixed_15(0.1), "0.1");
        assert_eq!(fixed_15(1e20), "100000000000000000000");
        assert_eq!(fixed_15(-2.5), "-2.5");
        assert_eq!(fixed_15(1e-16), "0");
        assert_eq!(fixed_15(1.23456789e-10), "0.000000000123457");
        assert_eq!(fixed_15(0.9999999999999999), "1");
    }
}
