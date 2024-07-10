package com.adscore.signature;

class Field {

  private String name;
  private String type;

  Field(String name, String type) {
    this.name = name;
    this.type = type;
  }

  String getName() {
    return name;
  }

  String getType() {
    return type;
  }
}
