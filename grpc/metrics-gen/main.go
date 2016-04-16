package main

import (
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"text/template"
)

// generating an AST is hard, lets just generate code
// the old fashioned way :|

// fix this to actually use right package name
var pkgName = "core"

type method struct {
	Name    string
	Args    string
	ArgDefs string
	Results string
}

type itf struct {
	Name     string
	CoreType string
	Methods  []method
}

type tmpl struct {
	Package    string
	Interfaces []itf
}

func unwrapExpr(e ast.Expr) string {
	switch t := e.(type) {
	case *ast.Ident:
		if t.IsExported() {
			return fmt.Sprintf("%s.%s", pkgName, t.String())
		}
		return t.String()
	case *ast.SelectorExpr:
		return unwrapSelector(t)
	case *ast.ArrayType:
		return unwrapArray(t)
	case *ast.StarExpr:
		return unwrapStar(t)
	case *ast.MapType:
		return unwrapMap(t)
	default:
		panic(fmt.Sprintf("unsupported type: %s", reflect.TypeOf(t).String()))
	}
}

func unwrapSelector(s *ast.SelectorExpr) string {
	return fmt.Sprintf("%s.%s", unwrapExpr(s.X), s.Sel.Name)
}

func unwrapArray(a *ast.ArrayType) string {
	return fmt.Sprintf("[]%s", unwrapExpr(a.Elt))
}

func unwrapStar(s *ast.StarExpr) string {
	return fmt.Sprintf("*%s", unwrapExpr(s.X))
}

func unwrapMap(m *ast.MapType) string {
	return fmt.Sprintf("map[%s]%s", unwrapExpr(m.Key), unwrapExpr(m.Value))
}

var typeCounter = 0

func main() {
	inputPath := flag.String("input", "", "")
	flag.Parse()

	context := tmpl{Package: "Test"}

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, *inputPath, nil, 0)
	if err != nil {
		fmt.Println(err)
		return
	}
	for _, d := range f.Decls {
		if t, ok := d.(*ast.GenDecl); ok {
			for _, s := range t.Specs {
				ts, ok := s.(*ast.TypeSpec)
				if !ok {
					continue
				}
				i, ok := ts.Type.(*ast.InterfaceType)
				if !ok {
					continue
				}
				fmt.Println(ts.Name)
				inter := itf{Name: ts.Name.String()}
				for _, m := range i.Methods.List {
					if len(m.Names) == 0 {
						continue
					}
					meth := method{Name: m.Names[0].String()}
					fmt.Println("\t", m.Names)
					f, ok := m.Type.(*ast.FuncType)
					if !ok {
						continue
					}

					args, argDefs := []string{}, []string{}
					if f.Params != nil && f.Params.NumFields() > 0 {
						fmt.Println("\tin:")
						for _, pi := range f.Params.List {
							argName := ""
							if len(pi.Names) > 0 {
								argName = pi.Names[0].String()
							} else {
								argName = fmt.Sprintf("arg%d", typeCounter)
								typeCounter++
							}
							fmt.Println("\t\t", argName, unwrapExpr(pi.Type))
							args = append(args, argName)
							argDefs = append(argDefs, fmt.Sprintf("%s %s", argName, unwrapExpr(pi.Type)))
						}
					}
					meth.Args = strings.Join(args, ",")
					meth.ArgDefs = strings.Join(argDefs, ", ")

					returns := []string{}
					if f.Results != nil && f.Results.NumFields() > 0 {
						fmt.Println("\tout:")
						for _, ri := range f.Results.List {
							fmt.Println("\t\t", ri.Names, unwrapExpr(ri.Type))
							returns = append(returns, unwrapExpr(ri.Type))
						}
					}
					meth.Results = strings.Join(returns, ", ")
					inter.Methods = append(inter.Methods, meth)
				}
				context.Interfaces = append(context.Interfaces, inter)
			}
		}
	}

	fmt.Println(context)
	t, err := template.ParseFiles("metrics/grpc-gen/metrics.tmpl")
	if err != nil {
		fmt.Println(err)
		return
	}
	t.Execute(os.Stdout, context)
}
