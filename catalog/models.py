from sqlalchemy import Column, String, Integer, DateTime
from sqlalchemy import Sequence, ForeignKey, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
from sqlalchemy import event

Base = declarative_base()

engine = create_engine("sqlite:///catalog.db")


class Category(Base):
    __tablename__ = "category"

    id = Column(Integer, Sequence(start=1, increment=1,
                name="catalog_id_sequence"),
                primary_key=True)
    name = Column(String, nullable=False)
    items = relationship('Item', backref='categorys')

    def get_items(self):
        return [i.serialize for i in self.items]

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'items': self.get_items()
        }


class User(Base):
    __tablename__ = "user"

    id = Column(Integer, Sequence(start=1, increment=1,
                name="user_id_sequence"), primary_key=True)
    email = Column(String, nullable=False)
    username = Column(String, nullable=False)
    pix = Column(String, nullable=True)
    items = relationship('Item', backref='users')

    def get_items(self):
        return [i.serialize for i in self.items]

    @property
    def serialize(self):
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'pix': self.pix,
            'items': self.get_items()
        }


class Item(Base):
    __tablename__ = "item"

    id = Column(Integer,
                Sequence(start=1, increment=1, name="item_id_sequence"),
                primary_key=True)
    name = Column(String, nullable=False)
    description = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("user.id"))
    category_id = Column(Integer, ForeignKey("category.id"))
    created_date = Column(DateTime, nullable=True)
    updated_Date = Column(DateTime, nullable=True)
    user = relationship(User)
    cat = relationship(Category)

    @property
    def serialize(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'user_id': self.user_id,
            'created_date': self.created_date,
            'updated_date': self.updated_Date
        }

Base.metadata.create_all(engine)
