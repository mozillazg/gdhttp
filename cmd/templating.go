// Copyright © 2017 mozillazg
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package cmd

import (
	"regexp"
	"fmt"
	"strings"
)

var reToken = regexp.MustCompile("<([^<>]+)>")
const tokenLeft = "<"
const tokenRight = ">"

// 模板内容替换
// substitute("/api/v1/jobs/<id>", map[string]string{"id": 123})
// -> "/api/v1/jobs/123"
func substitute(s string, mapping map[string]interface{}) string {
	s = reToken.ReplaceAllStringFunc(s, func(m string) string {
		m = strings.TrimLeft(m, tokenLeft)
		m = strings.TrimRight(m, tokenRight)
		if v, ok := mapping[m]; ok {
			return fmt.Sprintf("%s", v)
		}
		return ""
	})
	return s
}
