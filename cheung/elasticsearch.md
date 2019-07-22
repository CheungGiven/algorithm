# Elasticsearch 核心技术与实战
# 概述
* Lucene base
* 高可用 & 水平扩展
* Hot & Warm构架
* RESTful API
* JDBC & ODBC
* 海量数据的分布式存储及集群管理
  - 服务与数据的高可用，水平扩展
* 近实时搜索，性能卓越
  - 结构化/全文/地理位置/自动完成
* 海量数据的近实时分析
  - 聚合功能 
* Elastic Stack 生态圈
  - 可视化   kibana
  - 存储计算 Elasticsearch
  - 数据抓取 Logstash Beat
  - 商业包   X-Pack(安全,告警,监控,机械学习)
  - 云服务 https://www.elastic.co/guide/en/cloud-on-k8s/current/index.html
* [Elasticsearch Certification](https://training.elastic.co/exam/elastic-certified-engineer)
* 分开源版本和Basic版本
  - 部分X-Pack功能支持免费使用
* Elasticsearch与数据库的集成
  - APP => 数据库 (同步机制)=> Elasticsearch
* 指标分析/日志分析
  - beats => redis/kafka/RabbitMQ => logstash => Elasticsearch => kibana/Grafana 


# 安装
* Elasticsearch
```
//启动单节点
bin/elasticsearch -E node.name=node0 -E cluster.name=geektime -E path.data=node0_data
//安装插件
bin/elasticsearch-plugin install analysis-icu

//查看插件
bin/elasticsearch-plugin list
//查看安装的插件
GET http://localhost:9200/_cat/plugins?v

//start multi-nodes Cluster
bin/elasticsearch -E node.name=node0 -E cluster.name=geektime -E path.data=node0_data
bin/elasticsearch -E node.name=node1 -E cluster.name=geektime -E path.data=node1_data
bin/elasticsearch -E node.name=node2 -E cluster.name=geektime -E path.data=node2_data
bin/elasticsearch -E node.name=node3 -E cluster.name=geektime -E path.data=node3_data

ps | grep elasticsearch
kill pid
```
jvm.options

* kibana
```
// 启动 kibana
bin/kibana

// 查看插件
bin/kibana-plugin list
```
* logstash


# 基本概念
## 索引，文档和 REST API
* 索引/类型/文档(index/type/id)
* 索引
  - 索引是文档的容器,是一类文档的结合
  - index体现了逻辑空间的概念,每个索引都有自己的Mapping定义
  - Shard体现了物理空间的概念,索引数据分散在shard上
  - Mapping用于定义包含文档的字段名和字段类型
  - Setting定义不同的数据分布
  - Type已被废除
* 文档
  - 文档是所有可搜索数据的最小单位
  - 文档会被序列化成json格式, json对象由字段组成，对应字段类型
  - 每一个文档都有一个Unique ID
  - 文档的元数据

## 节点，集群分片和副本
* 节点
  - 本质上是一个JAVA进程
  - 生产环境一般建议只运行一个实例
  - 每一个节点都有名字 -E node.name=node1
  - 每一个节点启动之后,会分配一个UID,保存在data目录下
  - Master Node & Master-eligible nodes
    - 每一个节点启动后默认是Master-eligible
    - Master-eligible节点可以参加选主流程，成为Master节点
    - 每个节点上都保存了集群的状态，只有Master节点才能修改
    - Cluster State: 节点信息,Mapping Setting,分片路由
  - Data Node & Coordinating Node
    - Data Node:保存分片数据的节点，在数据扩展上起到了关键作用
    - Coordinating Node: 接受Client请求后分发到合适的节点,最终把结果汇到一起
    - 每个节点默认都起到了Coordinating Node的职责
  - 其它节点类型
    - Hot & Warm Node: 不同磁盘硬件配置的Data Note,降低集群部署的成本
    - Machine Leaning Node
    - Tribe Node， 5.3开始使用Cross Cluster Search
* 分片
  - Primary Shard(主分片)
    - 解决水平扩展问题,通过主分片,可以将数据分布到集群内的所有节点上
    - 主分片数在index创建时指定,后续不允许修改,除非reindex
    - 过小导致后续无法增加节点实现水平扩展，单分片数据量过大导致数据分配耗时
    - 过大影响搜索结果的相关性打分,资源浪费
    - 单个存储30G内来计算需要的分片数
  - Replica Shard(副本)
    - 可动态调整
    - 通过增加副本，一定程度上提高服务的可用性(读取的吞吐)

## 文档的curd
| Index  | PUT my_index/_doc/1 {"user":"mike", "comment":"You Konw ..."}     | 
| ------ |  :--------------------------------------------------------------  |
| Create | POST my_index/_doc  {"user":"mike", "comment":"You Konw ..."}     |
| Read   | Get my_index/_doc/1                                               |   
| Update | Post my_index/_update/1 {"user":"mike", "comment":"You Konw ..."} |
| Delete | Delete my_index/_doc/1                                            |

* index: 不存在就索引新文档，存在就更新
* Bulk
  ```
  POST _bulk
  { "index" : { "_index" : "test", "_id" : "1" } }
  { "field1" : "value1" }
  { "delete" : { "_index" : "test", "_id" : "2" } }
  { "create" : { "_index" : "test2", "_id" : "3" } }
  { "field1" : "value3" }
  { "update" : {"_id" : "1", "_index" : "test"} }
  { "doc" : {"field2" : "value2"} }
  ```
* mget
  ```
  GET /_mget
  {
      "docs" : [
          {
              "_index" : "test",
              "_id" : "1"
          },
          {
              "_index" : "test",
              "_id" : "2"
          }
      ]
  }
  ```
* msearch
  ```
  POST kibana_sample_data_ecommerce/_msearch
  {}
  {"query" : {"match_all" : {}},"size":1}
  {"index" : "kibana_sample_data_flights"}
  {"query" : {"match_all" : {}},"size":2}
  ```
## 倒排索引
* 单词词典(Tern Dictionary)
  - 记录单词与倒排列表的关系
  - B+ or 哈希来实现
* 倒排列表(Posting List)
  - 文档ID
  - 词频TF
  - 位置(Position): 文档中的分词位置,用于语句搜索(phrase query)
  - 偏移(offset): 高亮显示

## Analyzer进行分词
* 把全文本转换成一系列单词(Term/token)的过程
* CharacterFilters(原始文本处理) => Tokenizer(按规则切分单词) => TokenFilters(单词加工,小写同意词等)
* Simple Analyzer
  – 按照非字母切分（符号被过滤），小写处理
* Stop Analyzer
  – 小写处理，停用词过滤（the，a，is）
* Whitespace Analyzer
  – 按照空格切分，不转小写
* Keyword Analyzer 
  – 不分词，直接将输入当作输出
* icu_analyzer(亚洲文字)
* 中文分词
  - IKAnalyzer
  - 
* Language
  – 提供了30多种常见语言的分词器 
```
Get /_analyze
curl -XGET 'localhost:9200/_analyze?analyzer=jp_search_analyzer' -d '5ヶ月'
```
# Search API
* 指定索引
  ```
  /_search 集群上所以索引
  /index1/_search
  /index1,index2/_search
  /index*/_search
  ```
* Response
  - took: 整个搜索请求耗费了多少毫秒
  - total: 符合条件的总文档数
  - hits: 结果集，默认为前10个文档
  - _index, _id, _score, _souce

## URI Search
```
curl -XGET "localhost:9200/index/_search?q=field1:hoge&profile=true
```
* 泛查询，正对_all,所有字段
  - GET /index/_search?q=2012 
* 指定字段
  - GET /index/_search?q=title:2012&sort=year:desc&from=0&size=10&timeout=1s 
* Term v.s Phrase
  - Term: GET /movies/_search?q=title:Beautiful Mind => Beautiful OR Mind
  - Phrase: GET /movies/_search?q=title:"Beautiful Mind" => Beautiful AND Mind
* 分组，Bool查询
  - GET /movies/_search?q=title:(Beautiful Mind)
* Bool
  - AND / OR / NOT && / || / ！
  - + must
  - - must_not
  - title:(+matrix -reloaded)
* Range []闭区间, {}开区间
  - year:{2019 TO 2018}
  - year:[* TO 2018]
* 算数符号
  - year:>2010
  - year:(>2010 && <=2018)
  - year:(+>2010 +<=2018)
* 通配符查询
  - title:be*
* 正则表达
  - title:[bt]oy 
* 模糊匹配与近似查询
  - title:befutifl~1
  - title:"lord rings"~2
* [文档](https://www.elastic.co/guide/en/elasticsearch/reference/7.0/search-uri-request.html)


## Request Body & Query DSL
* match 分词查询
* tern 不分词精确匹配
  - term主要用于精确匹配哪些值，比如数字，日期，布尔值或 not_analyzed 的字符串
* paging
  ```
  curl -XGET "localhost:9200/index/_search" -H 'Content-Type: application/json' -d'
  {
    "from": 10,
    "size": 30,
    "query": {
      "match_all": {}
    }
  }'
  ```
* sort
  ```
  POST kibana_sample_data_ecommerce/_search
  {
    "sort":[{"order_date":"desc"}],
    "query":{
      "match_all": {}
    }
  }
  ```
* range
  - gt :: 大于
  - gte:: 大于等于
  - lt :: 小于
  - lte:: 小于等于
  ```
  GET books/_search
  {
    "_source": ["title", "publish_time"],
    "query": {
      "range": {
        "publish_time": {
          "gte": "2016-1-1",
          "lte": "2016-12-31",
          "format": "yyyy-MM-dd"
        }
      }
    }
  }
  ```
* source filtering
  ```
  POST kibana_sample_data_ecommerce/_search
  {
    "_source":["order_date"],
    "query":{
      "match_all": {}
    }
  }
  ```
* 脚本字段
  ```
  GET kibana_sample_data_ecommerce/_search
  {
    "script_fields": {
      "new_field": {
        "script": {
          "lang": "painless",
          "source": "doc['order_date'].value+'hello'"
        }
      }
    },
    "query": {
      "match_all": {}
    }
  }
  ```
* match
  ```
  POST movies/_search
  {
    "query": {
      "match": {
        "title": {
          "query": "last christmas",
          "operator": "and"
        }
      }
    }
  }
  ```
* match_phrase 自带了 operator 属性的值为 and 的 match
  ```
  POST movies/_search
  {
    "query": {
      "match_phrase": {
        "title":{
          "query": "one love",
          "slop": 1
  
        }
      }
    }
  }
  ```
* perfix
  ```
  GET books/_search
  {
    "_source": "description", 
    "query": {
      "prefix": {
        "description": "wi"
      }
    }
  }
  ```
* [文档](https://www.elastic.co/guide/en/elasticsearch/reference/7.0/search-request-body.html)

## Query String & Simple Query String
* Query string
  ```
  POST users/_search
  {
    "query": {
      "query_string": {
        "default_field": "name",
        "query": "Ruan AND Yiming"
      }
    }
  }
  ```
* Simple Query String
  - 类似Query String但是会忽略错误语法
  - 不支持AND OR NOT
  - Term之间默认的关系是OR，可以指定Operator
  - + 替代 AND, | 替代 OR, - 替代 NOT
  ```
  POST users/_search
  {
    "query": {
      "simple_query_string": {
        "query": "Ruan Yiming",
        "fields": ["name"],
        "default_operator": "AND"
      }
    }
  }
  ```

# Mapping
* 预定义字段的类型以及相关属性 solr schema
  ```
  {
      "mappings": {
          "my_type": {
          //true:表示自动识别新字段并创建索引，false:不自动索引新字段，strict:遇到未知字段，抛异常，不能存入
              "dynamic":      "strict", 
              
                //动态模板
               "dynamic_templates": [
                      { "stash_template": {
                        "path_match":  "stash.*",
                        "mapping": {
                          "type":           "string",
                          "index":       "not_analyzed"
                        }
                      }}
                    ],
              //属性列表
              "properties": {
                  //一个strign类型的字段
                  "title":  { "type": "string"},
                  
                  "stash":  {
                      "type":     "object",
                      "dynamic":  true 
                  }
              }
          }
      }
  }
  ```
* 类型
  - String 
  - text, keyword
  - long, integer, short, byte, double, float
  - date
  - boolean
  - binary
  - object, nested
  - geo-point, geo-sharp
  - ip, competion
* 属性
  - index_name 
  - anylyzer
  - store 显示存储
  - boost
  - null_value
  - include_in_all
  - format
  ```
  {
      "mappings": {
          "my_type": {
          //true:表示自动识别新字段并创建索引，false:不自动索引新字段，strict:遇到未知字段，抛异常，不能存入
              "dynamic":      "strict", 
              
                //动态模板
               "dynamic_templates": [
                      { "stash_template": {
                        "path_match":  "stash.*",
                        "mapping": {
                          "type":           "string",
                          "index":       "not_analyzed"
                        }
                      }}
                    ],
              //属性列表
              "properties": {
                  //一个strign类型的字段
                  "title":  { "type": "string"},
                  
                  "stash":  {
                      "type":     "object",
                      "dynamic":  true 
                  }
              }
          }
      }
  }
  ```
## Dynamic Mapping
* 在写入文档的时候,如果索引不存在会自动创建索引
* 无需手动定义Mapping,Elasticsearch会自动根据文档信,推算出字段的类型
* 但是有时候会推算的不准确,例如地理位置信息
* 当类型如果设置不对时,会导致一些功能无法正常运行,例如Range查询
* 后期修改Mapping的字段类型
  - 新增字段
    - Dynamic: true,  一旦有新增字段的文档写入,Mapping也同时被更新
    - Dynamic: false, Mapping不会被更新,新增字段的数据无法被索引,但是信息会出现在_source中
    - Dynamic: Strict, 文档写入失败
  - 对已有字段,一旦已有数据写入,就不再支持修改字段定义

## 显式Mapping
* 推荐步骤
  - 创建一个临时的index,写入一些样本数据
  - 通过访问Mapping API 获得该文件的动态Mapping定义
  - 修改后使用该配置创建你的索引
  - 删除临时索引
* null_value
  - 只要keyword类型支持设定null_value
  ```
  PUT users
  {
      "mappings" : {
        "properties" : {
          "firstName" : {
            "type" : "text"
          },
          "lastName" : {
            "type" : "text"
          },
          "mobile" : {
            "type" : "keyword",
            "null_value": "NULL"
          }
  
        }
      }
  }
  ```
* _all在7中被copy_to所替代
* es中不提供专门的数组类型,但是任何字段,都可以包含多个相同类型的数值

## 多字段特性
* 实现精确匹配
  - 增加一个keyword字段
* 使用不同的analyzer
  - 不同语言
  - pinyin 字段的搜索
  - 还支持为搜索和索引指定不同的analyzer
* Exact Values(精确值) vs Full Text
  - Exact Values: keyword
  - Full Text: text
* 自定义分词
  - Character Filter
    - 增加及替换字符
    - 可配置多个Character Filter
    - 会影响Tokenizer的position和offset信息
    - 自带: HTML strip, Mapping, Pattern replace
  - Tokenizer
    - 切词
    - 可用java开发插件实现自己的Tokenizer
  - Token Filter
    - 将Tokenizer输出的词(term)进行增删该
  ```
  "jp_search_analyzer" : {
      "type" : "custom",
      "tokenizer" : "kuromoji_user_dict",
      "filter": [ "jp_search_stop_filter", "synonym_series_filter", "jp_synonym_filter", "jp_synonym_search_filter" ],
      "char_filter": ["jp_mapping", "jp_mapping2", "number_norm"]
  },
  "jp_index_analyzer" : {
      "type" : "custom",
      "tokenizer" : "kuromoji_user_dict",
      "filter": [ "jp_search_stop_filter", "synonym_series_filter", "jp_synonym_filter" ],
      "char_filter": ["jp_mapping", "jp_mapping2", "number_norm", "url_filter", "user_filter"]
  },
  ```

## Index Template和 Dynamic Template
* Index Template
  - 帮助你设定Mappings和Settings并按照一定的规则自动匹配到新创建的索引之上
  - 模版仅在一个索引被新创建时,才会产生作用，修改模版不会影响已创建的索引
  - 可以设定多个索引模版,这些设置会被merge在一起
  - 可以指定order的数值,控制merging的过程
  ```
  PUT /_template/template_test
  {
      "index_patterns" : ["test*"],
      "order" : 1,
      "settings" : {
        "number_of_shards": 1,
          "number_of_replicas" : 2
      },
      "mappings" : {
        "date_detection": false,
        "numeric_detection": true
      }
  }
  ```
* Index Template工作方式
  - 应用Elasticsearch默认的setting和mapping
  - 应用order数值低的Index Template中的设定
  - 应用order数值高的Index Template中的设定
  - 应用创建索引时,用户所指定的settings和mappings,并覆盖之前模版中的设定
* Dynamic Template
  - 根据Elasticsearch识别的数据类型,结合字段名称,来动态设定字段类型
  - 所有的字符串类型都设定成keyword,或者关闭keyword字段
  - is开头的字段都设置成boolean
  - long_开头的都设置成long类型
  ```
  {
    "mappings": {
      "dynamic_templates": [
              {
          "strings_as_boolean": {
            "match_mapping_type":   "string",
            "match":"is*",
            "mapping": {
              "type": "boolean"
            }
          }
        },
        {
          "strings_as_keywords": {
            "match_mapping_type":   "string",
            "mapping": {
              "type": "keyword"
            }
          }
        }
      ]
    }
  }
  ```
* [Index Template文档](https://www.elastic.co/guide/en/elasticsearch/reference/7.1/indices-templates.html)
* [Dynamic Template文档](https://www.elastic.co/guide/en/elasticsearch/reference/7.1/dynamic-mapping.html)

## 聚合分析(Aggregation)
* 通过聚合,可以得到一个数据的概览
* 高性能,只需要一条语句就能从Elasticsearch得到分析结果,无需在客户端实现
* Bucket Aggregation
  - 一些满足特定条件的文档的集合
  - Term & Range
* Metric Aggregation
  - 一些数学运算，可以多文档字段进行统计分析
  - 同样也支持在脚本(painless script)产生的结果之上进行计算
  - 大多数metric是数学计算,仅输出一个值 min / max / sum / avg / cardinality
  - 部分metric支持输出多个数值 stats / percentiles / percentiles_ranks
* Pipeline Aggregation
  - 对其它的聚合结果进行二次聚合
* Matrix Aggregation
  - 支持对多个字段的操作并提供一个结果矩阵
  ```
  {
    "size": 0,
    "aggs":{
      "flight_dest":{
        "terms":{
          "field":"DestCountry"
        },
        "aggs":{
          "avg_price":{
            "avg":{
              "field":"AvgTicketPrice"
            }
          },
          "max_price":{
            "max":{
              "field":"AvgTicketPrice"
            }
          },
          "min_price":{
            "min":{
              "field":"AvgTicketPrice"
            }
          }
        }
      }
    }
  }
  ```
* [search-aggregations文档](https://www.elastic.co/guide/en/elasticsearch/reference/7.1/search-aggregations.html)

# 搜索与分词
## Term与Full Text
* Keyword vs Text
* Term
  - 表达语意的最小单位
  - Term Query / Range Query / Exists Query / Prefix Query / Wildcard Query
  - 对输入不会做分词,会将输入作为一个整体,在倒排索引中查找准确的词项,并进行相关度算分
  - 可以通过 Constant score将查询换成一个Filtering,避免算分,并利用缓存,提高性能
  ```
  POST /products/_search
  {
    //"explain": true,
    "query": {
      "term": {
        "productID.keyword": {
          "value": "XHDK-A-1293-#fJ3"
        }
      }
    }
  }
  
  POST /products/_search
  {
    "explain": true,
    "query": {
      "constant_score": {
        "filter": {
          "term": {
            "productID.keyword": "XHDK-A-1293-#fJ3"
          }
        }
  
      }
    }
  }
  ```
* Full Text
  - Match Query / Match Phrase Query / Query String Query
  - 索引和搜索时都会进行分词
  - 查询会对每个词项逐个进行底层的查询,在将结果进行合并,并为每一个文档生成一个算分
  - Precision & Recall

## 结构化搜索(Structured search)
* 指对于结构化数据的搜索
  - 日期,bool和数字都是结构化的
  - 文本也可以是结构化的
  - 对于有精准的格式的结构化数据,我们可以进行逻辑操作,包括比较范围或判定大小
    - gt 大于
    - lt 小于
    - gte 大于等于
    - lte 小于等于
  - 结构化的文本可以做精确匹配或部分匹配, Term / Prifix
  - 结构化结果只有是或否两个值
  - 处理多值字段，term 查询是包含，而不是等于
  ```
  #数字类型 Term
  POST products/_search
  {
    "profile": "true",
    "explain": true,
    "query": {
      "term": {
        "price": 30
      }
    }
  }
  
  #数字类型 terms
  POST products/_search
  {
    "query": {
      "constant_score": {
        "filter": {
          "terms": {
            "price": [
              "20",
              "30"
            ]
          }
        }
      }
    }
  }
  
  #数字 Range 查询
  GET products/_search
  {
      "query" : {
          "constant_score" : {
              "filter" : {
                  "range" : {
                      "price" : {
                          "gte" : 20,
                          "lte"  : 30
                      }
                  }
              }
          }
      }
  }
  
  # 日期 range
  POST products/_search
  {
      "query" : {
          "constant_score" : {
              "filter" : {
                  "range" : {
                      "date" : {
                        "gte" : "now-1y"
                      }
                  }
              }
          }
      }
  }
  #exists查询
  POST products/_search
  {
    "query": {
      "constant_score": {
        "filter": {
          "exists": {
            "field": "date"
          }
        }
      }
    }
  }
  ```
## 搜索的相关性算分
* 相关性 Relevance
  - TF-IDF, BM 25
* 词频 Term Frequency
* 逆文档频率 IDF
* score(q,d) = coord(q,d) * queryNorm(q) * E(tf(t in d)) * idf(t)2 * boost(t) * norm(t,d))
* BM 25
  - 和TF-IDF相比,当TF无限增加时,BM 25算分会趋于一个数值
* explain API
  - "explain": true
* Boosting Relevance

# 监控
* _cluster/health
* yellow
  * 所有的主分片已经分片了，但至少还有一个副本是缺失的。不会有数据丢失，所以搜索结果依然是完整的。不过，你的高可用性在某种程度上被弱化。如果 更多的 分片消失，你就会丢数据了。把 yellow 想象成一个需要及时调查的警告。
* red
  * 至少一个主分片（以及它的全部副本）都在缺失中。这意味着你在缺少数据：搜索只能返回部分数据，而分配到这个分片上的写入请求会返回一个异常。 
* GET _cluster/health?level=indices
* GET _nodes/stats
* GET my_index/_stats
* GET my_index,another_index/_stats 
* GET _all/_stats 
* GET /_cat/shards 查看所有分片状态

# config
```
# ======================== Elasticsearch Configuration =========================
#
# NOTE: Elasticsearch comes with reasonable defaults for most settings.
# Before you set out to tweak and tune the configuration, make sure you
# understand what are you trying to accomplish and the consequences.
#
# The primary way of configuring a node is via this file. This template lists
# the most important settings you may want to configure for a production cluster.
#
# Please see the documentation for further information on configuration options:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/setup-configuration.html>
#
# ---------------------------------- Cluster -----------------------------------
#
# Use a descriptive name for your cluster:
# 集群名称，默认是elasticsearch
# cluster.name: my-application
#
# ------------------------------------ Node ------------------------------------
#
# Use a descriptive name for the node:
# 节点名称，默认从elasticsearch-2.4.3/lib/elasticsearch-2.4.3.jar!config/names.txt中随机选择一个名称
# node.name: node-1
#
# Add custom attributes to the node:
# 
# node.rack: r1
#
# node.name: "node1"
# 是否有资格成为主节点
# node.master: true
# 是否存储索引数据
# node.data: true
# 默认索引分片数
# index.number_of_shards: 3
# 默认索引副本数
# index.number_of_replicas: 1
# ----------------------------------- Paths ------------------------------------
#
# Path to directory where to store the data (separate multiple locations by comma):
# 可以指定es的数据存储目录，默认存储在es_home/data目录下
# path.data: /path/to/data
#
# Path to log files:
# 可以指定es的日志存储目录，默认存储在es_home/logs目录下
# path.logs: /path/to/logs
#
# ----------------------------------- Memory -----------------------------------
#
# Lock the memory on startup:
# 锁定物理内存地址，防止elasticsearch内存被交换出去,也就是避免es使用swap交换分区
# bootstrap.memory_lock: true
#
#
#
# 确保ES_HEAP_SIZE参数设置为系统可用内存的一半左右
# Make sure that the `ES_HEAP_SIZE` environment variable is set to about half the memory
# available on the system and that the owner of the process is allowed to use this limit.
# 
# 当系统进行内存交换的时候，es的性能很差
# Elasticsearch performs poorly when the system is swapping the memory.
#
# ---------------------------------- Network -----------------------------------
#
#
# 为es设置ip绑定，默认是127.0.0.1，也就是默认只能通过127.0.0.1 或者localhost才能访问
# es1.x版本默认绑定的是0.0.0.0 所以不需要配置，但是es2.x版本默认绑定的是127.0.0.1，需要配置
# Set the bind address to a specific IP (IPv4 or IPv6):
#
# network.host: 192.168.0.1
#
#
# 为es设置自定义端口，默认是9200
# 注意：在同一个服务器中启动多个es节点的话，默认监听的端口号会自动加1：例如：9200，9201，9202...
# Set a custom port for HTTP:
#
# http.port: 9200
#
# For more information, see the documentation at:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-network.html>
#
# --------------------------------- Discovery ----------------------------------
#
# 当启动新节点时，通过这个ip列表进行节点发现，组建集群
# 默认节点列表：
# 127.0.0.1，表示ipv4的回环地址。
#	[::1]，表示ipv6的回环地址
#
# 在es1.x中默认使用的是组播(multicast)协议，默认会自动发现同一网段的es节点组建集群，
# 在es2.x中默认使用的是单播(unicast)协议，想要组建集群的话就需要在这指定要发现的节点信息了。
# 注意：如果是发现其他服务器中的es服务，可以不指定端口[默认9300]，如果是发现同一个服务器中的es服务，就需要指定端口了。
# Pass an initial list of hosts to perform discovery when new node is started:
# 
# The default list of hosts is ["127.0.0.1", "[::1]"]
#
# discovery.zen.ping.unicast.hosts: ["host1", "host2"]
#
#
#
#
# 通过配置这个参数来防止集群脑裂现象 (集群总节点数量/2)+1
# Prevent the "split brain" by configuring the majority of nodes (total number of nodes / 2 + 1):
#
# discovery.zen.minimum_master_nodes: 3
#
# For more information, see the documentation at:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-discovery.html>
#
# ---------------------------------- Gateway -----------------------------------
#
# Block initial recovery after a full cluster restart until N nodes are started:
# 一个集群中的N个节点启动后,才允许进行数据恢复处理，默认是1
# gateway.recover_after_nodes: 3
#
# For more information, see the documentation at:
# <http://www.elastic.co/guide/en/elasticsearch/reference/current/modules-gateway.html>
#
# ---------------------------------- Various -----------------------------------
# 在一台服务器上禁止启动多个es服务
# Disable starting multiple nodes on a single system:
#
# node.max_local_storage_nodes: 1
#
# 设置是否可以通过正则或者_all删除或者关闭索引库，默认true表示必须需要显式指定索引库名称
# 生产环境建议设置为true，删除索引库的时候必须显式指定，否则可能会误删索引库中的索引库。
# Require explicit names when deleting indices:
#
# action.destructive_requires_name: true
```
# 便利工具
## 命令
```
curl -XGET 'localhost:9200/_analyze?analyzer=jp_search_analyzer' -d '5ヶ月'
curl -XPUT "http://localhost:9200/lumine_search_all_stg_01_v20181128" -d @settings_20181128.json -H "Content-Type: application/json"; echo
```
```
curl -XPOST ’http://localhost:9200/_aliases’ -d ’{
    "actions" : [
      { "add" : { "index" : "bookpass_search_v20190625", "alias" : "bookpass_search" } }
] }’
```

## reroute
```
#!/usr/bin/env python
#name: recovery.py

import requests
import json
host = "http://localhost:9200/_cluster/allocation/explain"
s= requests.Session()
def reroute_shard(index,shard,node):
    data = {
    "commands" : [
        {
          "allocate_stale_primary" : {
              "index" : index, "shard" : shard, "node" : node, "accept_data_loss": True
          }
        }
    ]
   }
    print data
    url = "http://localhost:9200/_cluster/reroute"
    res = s.post(url,json=data)
    print res

def get_node(line):
    if "UNASSIGNED" in line:
        line = line.split()
        index = line[0]
        shard = line[1]
        if line[2] != "p":
            return
        body = {
           "index": index,
           "shard": shard,
           "primary": True
               }
        res = s.get(host, json = body)
        for store in res.json().get("node_allocation_decisions"):
            if store.get("store").get("allocation_id"):
               node_name = store.get("node_name")
               reroute_shard(index,shard,node_name)
    else:
        return

with open("shards", 'rb') as f:
    map(get_node,f)
```